use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::analysis::{Interpretation, Observation, SkewReport};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph, Wrap},
    Frame, Terminal,
};

const MAX_PLOT_POINTS: usize = 512;
const TICK_RATE: Duration = Duration::from_millis(200);

type UiResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct UiState {
    pub target_ip: Option<String>,
    pub target_port: u16,
    pub start_time: Instant,
    pub status: Arc<Mutex<String>>,
    pub observations: Arc<Mutex<Vec<Observation>>>,
    pub latest_report: Arc<Mutex<Option<SkewReport>>>,
    pub latest_interpretation: Arc<Mutex<Option<Interpretation>>>,
    pub running: Arc<AtomicBool>,
}

pub fn run(state: UiState) -> UiResult<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_loop(&mut terminal, &state);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &UiState,
) -> UiResult<()> {
    while state.running.load(Ordering::Relaxed) {
        terminal.draw(|frame| draw(frame, state))?;

        if event::poll(TICK_RATE)? {
            if let Event::Key(key) = event::read()? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q')) {
                    state.running.store(false, Ordering::Relaxed);
                }
            }
        }
    }
    Ok(())
}

fn draw(frame: &mut Frame, state: &UiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ])
        .split(frame.size());

    draw_info_panel(frame, chunks[0], state);
    draw_chart(frame, chunks[1], state);
    draw_intel_panel(frame, chunks[2], state);
}

fn draw_info_panel(frame: &mut Frame, area: Rect, state: &UiState) {
    let elapsed = state.start_time.elapsed();
    let elapsed_str = format_time(elapsed);
    let status_line = {
        state.status.lock().map(|s| s.clone()).unwrap_or_else(|_| "Status unavailable".into())
    };
    let sample_count = state
        .observations
        .lock()
        .map(|obs| obs.len())
        .unwrap_or(0);
    let target_ip = state
        .target_ip
        .as_deref()
        .unwrap_or("Passive Sniffing Mode");

    let text = vec![
        Line::from(format!(
            "Target: {target_ip}:{port}",
            port = state.target_port
        )),
        Line::from(format!("Status: {status_line}")),
        Line::from(format!("Samples: {sample_count}")),
        Line::from(format!("Elapsed: {elapsed_str}")),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().title("Session Info").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn draw_chart(frame: &mut Frame, area: Rect, state: &UiState) {
    let observations = state
        .observations
        .lock()
        .map(|obs| collect_recent(&obs))
        .unwrap_or_default();
    let report_opt = state
        .latest_report
        .lock()
        .ok()
        .and_then(|r| r.clone());

    let sample_points = build_sample_points(&observations, report_opt.as_ref());
    let regression_points = report_opt
        .as_ref()
        .map(|report| build_regression_points(&observations, report))
        .unwrap_or_default();

    let mut datasets = Vec::new();
    if !sample_points.is_empty() {
        datasets.push(
            Dataset::default()
                .name("Samples")
                .marker(symbols::Marker::Dot)
                .style(Style::default().fg(Color::Yellow))
                .graph_type(GraphType::Scatter)
                .data(&sample_points),
        );
    }

    if !regression_points.is_empty() {
        let color = report_opt
            .as_ref()
            .map(|r| if r.r_squared > 0.99 { Color::Green } else { Color::Red })
            .unwrap_or(Color::Gray);
        datasets.push(
            Dataset::default()
                .name("Regression")
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .graph_type(GraphType::Line)
                .data(&regression_points),
        );
    }

    let (x_bounds, y_bounds) = compute_bounds(&sample_points, &regression_points);

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title("Clock Offset (microseconds)")
                .borders(Borders::ALL),
        )
        .x_axis(
            Axis::default()
                .title(Span::styled("Time (s)", Style::default().fg(Color::Cyan)))
                .bounds(x_bounds),
        )
        .y_axis(
            Axis::default()
                .title(Span::styled("Offset", Style::default().fg(Color::Cyan)))
                .bounds(y_bounds),
        );

    frame.render_widget(chart, area);
}

fn draw_intel_panel(frame: &mut Frame, area: Rect, state: &UiState) {
    let interpretation = state
        .latest_interpretation
        .lock()
        .ok()
        .and_then(|interp| interp.clone());
    let report = state
        .latest_report
        .lock()
        .ok()
        .and_then(|r| r.clone());

    let stability = interpretation
        .as_ref()
        .map(|i| i.stability_desc.as_str())
        .unwrap_or("Collecting data...");
    let hardware = interpretation
        .as_ref()
        .map(|i| i.hardware_quality.as_str())
        .unwrap_or("Pending");
    let verdict = interpretation
        .as_ref()
        .map(|i| i.human_verdict.as_str())
        .unwrap_or("Need more samples for analysis.");
    let r_squared = report
        .as_ref()
        .map(|r| format!("{:.4}", r.r_squared))
        .unwrap_or_else(|| "--".into());
    let ppm = report
        .as_ref()
        .map(|r| format!("{:.2}", r.ppm))
        .unwrap_or_else(|| "--".into());

    let lines = vec![
        Line::from("--- 🧠 CHRONOS INTELLIGENCE ---"),
        Line::from(format!("Signal Quality: {stability}")),
        Line::from(format!("Hardware Est.:  {hardware}")),
        Line::from(format!("FINAL VERDICT:  {verdict}")),
        Line::from(""),
        Line::from(format!("Live R²: {r_squared} | Skew: {ppm} ppm")),
    ];

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Intelligence Panel").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn collect_recent(observations: &[Observation]) -> Vec<Observation> {
    let len = observations.len();
    let start = len.saturating_sub(MAX_PLOT_POINTS);
    observations[start..]
        .iter()
        .cloned()
        .collect()
}

fn build_sample_points(
    observations: &[Observation],
    report: Option<&SkewReport>,
) -> Vec<(f64, f64)> {
    if observations.is_empty() {
        return Vec::new();
    }

    let freq = report
        .map(|r| r.nominal_frequency)
        .unwrap_or(1_000.0)
        .max(1.0);
    let base_time = observations.first().map(|obs| obs.local_time).unwrap_or(0.0);

    observations
        .iter()
        .map(|obs| {
            let elapsed = (obs.local_time - base_time).max(0.0);
            let remote_seconds = obs.remote_ts / freq;
            let offset_us = (remote_seconds - obs.local_time) * 1_000_000.0;
            (elapsed, offset_us)
        })
        .collect()
}

fn build_regression_points(observations: &[Observation], report: &SkewReport) -> Vec<(f64, f64)> {
    if observations.len() < 2 {
        return Vec::new();
    }

    let freq = report.nominal_frequency.max(1.0);
    let base_time = observations.first().map(|obs| obs.local_time).unwrap_or(0.0);
    let elapsed_end = observations
        .last()
        .map(|obs| (obs.local_time - base_time).max(0.0))
        .unwrap_or(0.0);

    let base_offset = observations.first().map(|obs| {
        let remote_seconds = obs.remote_ts / freq;
        (remote_seconds - obs.local_time) * 1_000_000.0
    }).unwrap_or(0.0);

    let slope_us_per_sec = report.ppm;
    vec![
        (0.0, base_offset),
        (
            elapsed_end.max(0.0),
            base_offset + slope_us_per_sec * elapsed_end,
        ),
    ]
}

fn compute_bounds(
    samples: &[(f64, f64)],
    regression: &[(f64, f64)],
) -> ([f64; 2], [f64; 2]) {
    let mut max_x = samples
        .last()
        .map(|(x, _)| *x)
        .unwrap_or(1.0)
        .max(1.0);
    if let Some(last) = regression.last() {
        max_x = max_x.max(last.0);
    }

    let mut min_y: f64 = 0.0;
    let mut max_y: f64 = 0.0;
    for &(_, y) in samples.iter().chain(regression.iter()) {
        min_y = min_y.min(y);
        max_y = max_y.max(y);
    }

    if min_y == max_y {
        min_y -= 1.0;
        max_y += 1.0;
    }

    let padding = (max_y - min_y).max(1.0) * 0.1;
    ([0.0, max_x + 0.1], [min_y - padding, max_y + padding])
}

fn format_time(duration: Duration) -> String {
    let secs = duration.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}
