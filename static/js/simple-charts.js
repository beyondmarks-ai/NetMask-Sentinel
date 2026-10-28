(function (root) {
    "use strict";
    if (root.Chart) return;

    function sizeCanvas(chart) {
        var canvas = chart.canvas;
        var ratio = root.devicePixelRatio || 1;
        var width = Math.max(280, canvas.clientWidth || canvas.parentNode.clientWidth || 600);
        var height = Math.max(240, canvas.clientHeight || canvas.parentNode.clientHeight || 360);
        if (canvas.width !== width * ratio || canvas.height !== height * ratio) {
            canvas.width = width * ratio;
            canvas.height = height * ratio;
        }
        chart.ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        return {width: width, height: height};
    }

    function text(ctx, value, x, y, color, align, size) {
        ctx.fillStyle = color || "#536174";
        ctx.font = (size || 11) + "px Arial, sans-serif";
        ctx.textAlign = align || "left";
        ctx.textBaseline = "middle";
        ctx.fillText(String(value), x, y);
    }

    function drawLine(chart, bounds) {
        var ctx = chart.ctx;
        var labels = chart.data.labels || [];
        var datasets = chart.data.datasets || [];
        var left = 42, right = 14, top = 36, bottom = 42;
        var width = bounds.width - left - right;
        var height = bounds.height - top - bottom;
        var max = 1;
        datasets.forEach(function (set) {
            (set.data || []).forEach(function (value) { max = Math.max(max, Number(value) || 0); });
        });

        ctx.lineWidth = 1;
        for (var grid = 0; grid <= 4; grid += 1) {
            var gy = top + height * grid / 4;
            ctx.strokeStyle = "rgba(148,163,184,.24)";
            ctx.beginPath(); ctx.moveTo(left, gy); ctx.lineTo(left + width, gy); ctx.stroke();
            text(ctx, Math.round(max * (4 - grid) / 4), left - 8, gy, "#64748b", "right", 10);
        }

        labels.forEach(function (label, index) {
            var x = left + (labels.length <= 1 ? width / 2 : width * index / (labels.length - 1));
            if (labels.length <= 6 || index % 2 === 0 || index === labels.length - 1) {
                text(ctx, label, x, top + height + 22, "#64748b", "center", 10);
            }
        });

        datasets.forEach(function (set, setIndex) {
            var values = set.data || [];
            var color = set.borderColor || (setIndex ? "#22c55e" : "#ef4444");
            ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = 2.5;
            ctx.beginPath();
            values.forEach(function (value, index) {
                var x = left + (values.length <= 1 ? width / 2 : width * index / (values.length - 1));
                var y = top + height - (Number(value) || 0) / max * height;
                if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            });
            ctx.stroke();
            values.forEach(function (value, index) {
                var x = left + (values.length <= 1 ? width / 2 : width * index / (values.length - 1));
                var y = top + height - (Number(value) || 0) / max * height;
                ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
            });
            var legendX = left + setIndex * 105;
            ctx.fillRect(legendX, 10, 14, 3);
            text(ctx, set.label || "Series", legendX + 20, 12, "#334155", "left", 11);
        });
    }

    function drawDoughnut(chart, bounds) {
        var ctx = chart.ctx;
        var set = (chart.data.datasets || [])[0] || {data: []};
        var values = (set.data || []).map(function (value) { return Math.max(0, Number(value) || 0); });
        var colors = set.backgroundColor || [];
        var total = values.reduce(function (sum, value) { return sum + value; }, 0);
        var legendHeight = Math.ceil(values.length / 2) * 22;
        var radius = Math.max(55, Math.min(bounds.width, bounds.height - legendHeight) * .32);
        var cx = bounds.width / 2, cy = Math.max(radius + 12, (bounds.height - legendHeight) / 2);
        var start = -Math.PI / 2;
        if (!total) {
            ctx.strokeStyle = "#e2e8f0"; ctx.lineWidth = Math.max(18, radius * .32);
            ctx.beginPath(); ctx.arc(cx, cy, radius * .72, 0, Math.PI * 2); ctx.stroke();
            text(ctx, "Waiting for data", cx, cy, "#64748b", "center", 12);
        } else {
            values.forEach(function (value, index) {
                if (!value) return;
                var end = start + Math.PI * 2 * value / total;
                ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, radius, start, end); ctx.closePath();
                ctx.fillStyle = colors[index] || "#32c9a3"; ctx.fill(); start = end;
            });
            ctx.globalCompositeOperation = "destination-out";
            ctx.beginPath(); ctx.arc(cx, cy, radius * .62, 0, Math.PI * 2); ctx.fill();
            ctx.globalCompositeOperation = "source-over";
        }
        var labels = chart.data.labels || [];
        labels.forEach(function (label, index) {
            var column = index % 2, row = Math.floor(index / 2);
            var x = 18 + column * bounds.width / 2, y = bounds.height - legendHeight + 14 + row * 22;
            ctx.fillStyle = colors[index] || "#94a3b8"; ctx.fillRect(x, y - 5, 10, 10);
            text(ctx, label, x + 16, y, "#536174", "left", 10);
        });
    }

    function SimpleChart(context, config) {
        this.ctx = context;
        this.canvas = context.canvas;
        this.type = config.type;
        this.data = config.data || {labels: [], datasets: []};
        this.options = config.options || {};
        this.update();
    }

    SimpleChart.prototype.update = function () {
        var bounds = sizeCanvas(this);
        this.ctx.clearRect(0, 0, bounds.width, bounds.height);
        if (this.type === "doughnut") drawDoughnut(this, bounds);
        else drawLine(this, bounds);
    };

    root.Chart = SimpleChart;
}(window));
