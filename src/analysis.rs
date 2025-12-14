// Purpose: Provide convex-hull-based clock-skew analysis and classification utilities.
// Author: Research Project
// Disclaimer: For educational and defensive research purposes only.

use std::fmt;

/// High-level measurement snapshot used by the skew estimator.
#[derive(Debug, Clone)]
pub struct Observation {
    pub local_time: f64,
    pub remote_ts: f64,
}

impl Observation {
    pub fn new(local_time: f64, remote_ts: f64) -> Self {
        Self {
            local_time,
            remote_ts,
        }
    }
}

/// Summary of a skew computation run.
#[derive(Debug, Clone)]
pub struct SkewReport {
    pub slope: f64,
    pub ppm: f64,
    pub r_squared: f64,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Copy)]
pub enum Verdict {
    StablePhysical,
    LikelyPhysical,
    Inconclusive,
}

impl Verdict {
    fn classify(ppm: f64, r_squared: f64) -> Self {
        if r_squared >= 0.97 && ppm.abs() >= 0.5 {
            Verdict::StablePhysical
        } else if r_squared >= 0.9 {
            Verdict::LikelyPhysical
        } else {
            Verdict::Inconclusive
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::StablePhysical => write!(f, "Stable Physical Quartz Signature"),
            Verdict::LikelyPhysical => write!(f, "Likely Physical Device"),
            Verdict::Inconclusive => write!(f, "Inconclusive / Needs More Data"),
        }
    }
}

/// Executes convex-hull regression on raw observations and returns clock-skew statistics.
///
/// The function first evaluates the data assuming TCP timestamps are the X axis. If the
/// candidate slope suggests the axes were swapped (slope < 1.0), it transparently reruns the
/// analysis with inverted axes to maintain realistic Hertz-based slopes and high R² fidelity.
pub fn calculate_skew(observations: &[Observation]) -> Option<SkewReport> {
    if observations.len() < 2 {
        return None;
    }

    let mut forward_points: Vec<Point> = observations
        .iter()
        .map(|obs| Point::new(obs.remote_ts, obs.local_time))
        .collect();
    let mut reverse_points: Vec<Point> = observations
        .iter()
        .map(|obs| Point::new(obs.local_time, obs.remote_ts))
        .collect();

    let forward = compute_statistics(&mut forward_points);
    if let Some(report) = forward {
        if report.slope >= 1.0 {
            return Some(report);
        }
    }

    compute_statistics(&mut reverse_points)
}

/// Computes slope, ppm, and regression fit metrics from a prepared set of points.
fn compute_statistics(points: &mut Vec<Point>) -> Option<SkewReport> {
    if points.len() < 2 {
        return None;
    }

    let hull = compute_lower_hull(points.clone());
    if hull.len() < 2 {
        return None;
    }

    let first = hull.first()?;
    let last = hull.last()?;
    let dx = last.x - first.x;
    if dx.abs() < f64::EPSILON {
        return None;
    }

    let slope = (last.y - first.y) / dx;
    let nominal = infer_nominal_frequency(slope);
    let ppm = slope_to_ppm(slope, nominal);
    let intercept = first.y - slope * first.x;
    let mean_y = hull.iter().map(|p| p.y).sum::<f64>() / hull.len() as f64;

    let ss_tot: f64 = hull.iter().map(|p| (p.y - mean_y).powi(2)).sum();
    let ss_res: f64 = hull
        .iter()
        .map(|p| {
            let expected = slope * p.x + intercept;
            (p.y - expected).powi(2)
        })
        .sum();
    let r_squared = if ss_tot.abs() < f64::EPSILON {
        1.0
    } else {
        (1.0 - (ss_res / ss_tot)).clamp(0.0, 1.0)
    };

    Some(SkewReport {
        slope,
        ppm,
        r_squared,
        verdict: Verdict::classify(ppm, r_squared),
    })
}

/// Converts a slope (ratio between sender/receiver rates) into parts-per-million drift.
pub fn slope_to_ppm(slope: f64, nominal: f64) -> f64 {
    if nominal.abs() < f64::EPSILON {
        return 0.0;
    }
    ((slope - nominal) / nominal) * 1_000_000.0
}

/// Infers the nominal TCP timestamp frequency so ppm offsets can be reported around the expected baseline.
fn infer_nominal_frequency(slope: f64) -> f64 {
    let candidate = slope.abs();
    if candidate >= 500.0 {
        1000.0
    } else if candidate >= 175.0 {
        250.0
    } else if candidate >= 75.0 {
        100.0
    } else {
        1.0
    }
}

/// Point on the receiver/sender timestamp plane used for convex hull analysis.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// Compute the lower convex hull (Monotone Chain) for a set of points.
fn compute_lower_hull(mut points: Vec<Point>) -> Vec<Point> {
    if points.len() <= 1 {
        return points;
    }

    points.sort_by(|a, b| {
        a.x.partial_cmp(&b.x)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.y.partial_cmp(&b.y).unwrap_or(std::cmp::Ordering::Equal))
    });

    let mut lower: Vec<Point> = Vec::with_capacity(points.len());
    for p in points {
        while lower.len() >= 2
            && cross_product(lower[lower.len() - 2], lower[lower.len() - 1], p) <= 0.0
        {
            lower.pop();
        }
        lower.push(p);
    }

    lower
}

fn cross_product(o: Point, a: Point, b: Point) -> f64 {
    (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x)
}
