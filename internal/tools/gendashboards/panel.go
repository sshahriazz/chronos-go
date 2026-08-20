package main

// Panel constructors. Each returns the exact JSON object Grafana's schema
// expects, with the keys in the order a human reads them.
//
// Two counters are threaded through everything and are the reason these are
// functions rather than literals:
//
//   - the layout cursor, which places panels left-to-right on Grafana's
//     24-column grid and wraps to a new row when the next panel will not fit;
//   - the target counter, which hands out `refId` letters A..Z per dashboard.
//
// Both are package state, reset per dashboard by resetLayout and by main. The
// order in which panels are CONSTRUCTED therefore determines the output, so the
// dashboard functions build their panel slice in reading order and nothing here
// may be evaluated out of order or concurrently.

var (
	prometheusDS = obj{{"type", "prometheus"}, {"uid", "chronos-prometheus"}}

	// Layout cursor: x is the next free column, h the height of the row being
	// filled, y the top of that row.
	posX, posH, posY int

	// targetN feeds refId. Reset per dashboard so every dashboard starts at "A".
	targetN int
)

// resetLayout returns the layout cursor to the top-left.
func resetLayout() {
	posX, posH, posY = 0, 0, 0
}

// gridPos places a w×h panel, wrapping to a new row when it does not fit.
func gridPos(w, h int) obj {
	x := posX
	if x+w > 24 {
		x = 0
		posY += posH
	}
	posX = x + w
	posH = h
	return obj{{"h", h}, {"w", w}, {"x", x}, {"y", posY}}
}

// targetOpts is one query's optional settings.
type targetOpts struct {
	legend  string
	instant bool
	format  string
}

type targetOption func(*targetOpts)

func legendFormat(s string) targetOption { return func(o *targetOpts) { o.legend = s } }
func instant() targetOption              { return func(o *targetOpts) { o.instant = true } }
func tableFormat() targetOption          { return func(o *targetOpts) { o.format = "table" } }

// query builds one Prometheus target and consumes the next refId letter.
func query(expr string, opts ...targetOption) obj {
	o := targetOpts{format: "time_series"}
	for _, fn := range opts {
		fn(&o)
	}
	t := obj{
		{"datasource", prometheusDS},
		{"expr", expr},
		{"refId", string(rune('A' + targetN%26))},
		{"format", o.format},
	}
	targetN++
	if o.legend != "" {
		t = append(t, member{"legendFormat", o.legend})
	}
	if o.instant {
		t = append(t, member{"instant", true}, member{"range", false})
	}
	return t
}

// panelOpts carries every optional panel setting. Each constructor starts from
// its own defaults and applies the caller's options over them.
type panelOpts struct {
	unit     string
	w, h     int
	desc     string
	stack    bool
	legend   string
	minVal   *int
	steps    arr
	textMode string
	graph    bool
}

type panelOption func(*panelOpts)

func unit(s string) panelOption     { return func(o *panelOpts) { o.unit = s } }
func width(v int) panelOption       { return func(o *panelOpts) { o.w = v } }
func height(v int) panelOption      { return func(o *panelOpts) { o.h = v } }
func desc(s string) panelOption     { return func(o *panelOpts) { o.desc = s } }
func stacked() panelOption          { return func(o *panelOpts) { o.stack = true } }
func legend(s string) panelOption   { return func(o *panelOpts) { o.legend = s } }
func minVal(v int) panelOption      { return func(o *panelOpts) { o.minVal = &v } }
func steps(s arr) panelOption       { return func(o *panelOpts) { o.steps = s } }
func textMode(s string) panelOption { return func(o *panelOpts) { o.textMode = s } }
func graph() panelOption            { return func(o *panelOpts) { o.graph = true } }

func apply(base panelOpts, opts []panelOption) panelOpts {
	for _, fn := range opts {
		fn(&base)
	}
	return base
}

// timeseries is the default panel: a line per series over the dashboard window.
func timeseries(title string, targets arr, opts ...panelOption) obj {
	o := apply(panelOpts{unit: "short", w: 12, h: 8, legend: "list"}, opts)

	custom := obj{
		{"lineWidth", 1},
		{"fillOpacity", 12},
		{"showPoints", "never"},
		{"spanNulls", true},
		{"gradientMode", "opacity"},
	}
	if o.stack {
		custom = append(custom, member{"stacking", obj{{"mode", "normal"}, {"group", "A"}}})
	}
	defaults := obj{
		{"unit", o.unit},
		{"custom", custom},
		{"color", obj{{"mode", "palette-classic"}}},
	}
	if o.minVal != nil {
		defaults = append(defaults, member{"min", *o.minVal})
	}
	return obj{
		{"type", "timeseries"},
		{"title", title},
		{"description", o.desc},
		{"datasource", prometheusDS},
		{"gridPos", gridPos(o.w, o.h)},
		{"fieldConfig", obj{{"defaults", defaults}, {"overrides", arr{}}}},
		{"options", obj{
			{"legend", obj{
				{"displayMode", o.legend},
				{"placement", "bottom"},
				{"calcs", arr{"lastNotNull", "max"}},
			}},
			{"tooltip", obj{{"mode", "multi"}, {"sort", "desc"}}},
		}},
		{"targets", targets},
	}
}

// stat is a single reduced value, optionally over a sparkline.
//
// The target is built INSIDE this function, after gridPos, which is why it takes
// an expression rather than a target: the refId letter it consumes has to fall
// in the same place in the sequence it always has.
func stat(title, expr string, opts ...panelOption) obj {
	o := apply(panelOpts{unit: "short", w: 4, h: 4, textMode: "auto"}, opts)

	thresholds := o.steps
	if thresholds == nil {
		thresholds = arr{obj{{"color", "text"}, {"value", nil}}}
	}
	defaults := obj{
		{"unit", o.unit},
		{"thresholds", obj{{"mode", "absolute"}, {"steps", thresholds}}},
		{"color", obj{{"mode", "thresholds"}}},
		{"mappings", arr{}},
	}
	graphMode := "none"
	if o.graph {
		graphMode = "area"
	}
	pos := gridPos(o.w, o.h)

	targetOpts := []targetOption{}
	if o.legend != "" {
		targetOpts = append(targetOpts, legendFormat(o.legend))
	}
	// A sparkline needs the range; a bare number is an instant query.
	if !o.graph {
		targetOpts = append(targetOpts, instant())
	}

	return obj{
		{"type", "stat"},
		{"title", title},
		{"description", o.desc},
		{"datasource", prometheusDS},
		{"gridPos", pos},
		{"fieldConfig", obj{{"defaults", defaults}, {"overrides", arr{}}}},
		{"options", obj{
			{"reduceOptions", obj{
				{"calcs", arr{"lastNotNull"}},
				{"fields", ""},
				{"values", false},
			}},
			{"colorMode", "value"},
			{"graphMode", graphMode},
			{"textMode", o.textMode},
			{"justifyMode", "auto"},
		}},
		{"targets", arr{query(expr, targetOpts...)}},
	}
}

// row is a full-width section header.
func row(title string) obj {
	return obj{
		{"type", "row"},
		{"title", title},
		{"collapsed", false},
		{"gridPos", gridPos(24, 1)},
		{"panels", arr{}},
	}
}

// table renders an instant query as rows, for label-carrying gauges where the
// LABELS are the information.
func table(title string, targets arr, opts ...panelOption) obj {
	o := apply(panelOpts{w: 12, h: 8}, opts)
	return obj{
		{"type", "table"},
		{"title", title},
		{"description", o.desc},
		{"datasource", prometheusDS},
		{"gridPos", gridPos(o.w, o.h)},
		{"fieldConfig", obj{
			{"defaults", obj{
				{"custom", obj{{"align", "auto"}, {"filterable", true}}},
				{"mappings", arr{}},
			}},
			{"overrides", arr{}},
		}},
		{"options", obj{{"showHeader", true}, {"cellHeight", "sm"}}},
		{"targets", targets},
	}
}

// dashboard wraps a panel list in the document Grafana provisions.
func dashboard(uid, title, description string, panels arr, tags arr) obj {
	resetLayout()
	return obj{
		{"uid", uid},
		{"title", title},
		{"description", description},
		{"tags", append(arr{"chronos"}, tags...)},
		{"timezone", "browser"},
		{"schemaVersion", 39},
		{"version", 1},
		{"editable", false},
		{"refresh", "30s"},
		{"time", obj{{"from", "now-1h"}, {"to", "now"}}},
		{"timepicker", obj{
			{"refresh_intervals", arr{"10s", "30s", "1m", "5m", "15m"}},
		}},
		{"panels", panels},
		{"annotations", obj{{"list", arr{}}}},
		{"templating", obj{{"list", arr{}}}},
	}
}

// Threshold ladders shared across dashboards.
var (
	// upSteps: red below 1, green at 1. For `up{job=...}`.
	upSteps = arr{
		obj{{"color", "red"}, {"value", nil}},
		obj{{"color", "green"}, {"value", 1}},
	}
	// invSteps: green at zero, orange once anything is counted.
	invSteps = arr{
		obj{{"color", "green"}, {"value", nil}},
		obj{{"color", "orange"}, {"value", 1}},
	}
	// depSteps: green at zero, red once anything is counted.
	depSteps = arr{
		obj{{"color", "green"}, {"value", nil}},
		obj{{"color", "red"}, {"value", 1}},
	}
	// degradedSteps is depSteps' softer twin: a degraded dependency still serves.
	degradedSteps = arr{
		obj{{"color", "green"}, {"value", nil}},
		obj{{"color", "orange"}, {"value", 1}},
	}
)

// health is the scrape-reachability stat: 1 means Prometheus can reach the job.
func health(title, job string) obj {
	return stat(title, `up{job="`+job+`"}`,
		width(3), height(4), steps(upSteps), textMode("value_and_name"),
		desc("1 = Prometheus is successfully scraping "+job+"."))
}

// scheduleProbes names the two Temporal schedule probes explicitly.
//
// They are the only signal that a background job will ever run: a schedule that
// was never created produces no error, no failed workflow and no other metric
// that moves.
const scheduleProbes = "email_reservation_sweep|identity_retention"
