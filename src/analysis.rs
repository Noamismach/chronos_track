/// Point on the receiver/sender timestamp plane used for convex hull analysis.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// Compute the lower convex hull (Monotone Chain) for a set of points.
pub fn compute_lower_hull(mut points: Vec<Point>) -> Vec<Point> {
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

/// Compute the clock skew slope from the convex hull points.
pub fn calculate_skew(hull: &[Point]) -> Option<f64> {
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
    Some(slope)
}

/// Convert a slope (ratio between sender/receiver rates) into parts-per-million drift.
pub fn slope_to_ppm(slope: f64) -> f64 {
    (slope - 1.0) * 1_000_000.0
}
