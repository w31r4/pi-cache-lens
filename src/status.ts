import type { HealthyThemeColor, Locale } from "./types.ts";

export interface StatusTheme {
	fg: (color: "dim" | "muted" | "text" | "accent" | "success" | "warning" | "error", text: string) => string;
}

export interface StatusChipState {
	calls: number;
	lastSinglePct: number | null;
	sessionPromptTotal: number;
	sessionCacheRead: number;
	lastShortTag: string;
	lastAnomaly: boolean;
	icon: string;
	locale: Locale;
	healthyColor: HealthyThemeColor;
}

function colorizeValue(
	theme: StatusTheme | undefined,
	pct: number,
	options: { anomaly: boolean; warmingUp: boolean; healthyColor: HealthyThemeColor },
	text: string,
): string {
	if (!theme) return text;
	if (pct >= 70) return theme.fg(options.healthyColor, text);
	if (!options.anomaly && options.warmingUp) return theme.fg("muted", text);
	if (pct >= 30) return theme.fg("warning", text);
	return options.anomaly ? theme.fg("error", text) : theme.fg("muted", text);
}

export function formatStatusChip(state: StatusChipState, theme?: StatusTheme): string {
	const zh = state.locale === "zh";
	const singleLabel = zh ? "单次 " : "last ";
	const sessionLabel = zh ? " / 会话 " : " / sess ";
	const idleBody = zh ? "单次 -- / 会话 --" : "last -- / sess --";

	const iconPrefix = state.icon
		? theme
			? theme.fg(state.healthyColor, `${state.icon} `)
			: `${state.icon} `
		: "";
	const dim = (t: string) => (theme ? theme.fg("dim", t) : t);

	if (state.calls === 0 || state.lastSinglePct === null) {
		return `${iconPrefix}${dim(idleBody)}`;
	}

	const sessionPct =
		state.sessionPromptTotal > 0 ? (state.sessionCacheRead * 100) / state.sessionPromptTotal : 0;
	const tag = state.lastShortTag ? `(${state.lastShortTag})` : "";
	const warmingUp = state.calls <= 3;

	const singleVal = colorizeValue(
		theme,
		state.lastSinglePct,
		{ anomaly: state.lastAnomaly, warmingUp, healthyColor: state.healthyColor },
		`${Math.round(state.lastSinglePct)}%${tag}`,
	);
	const sessionVal = colorizeValue(
		theme,
		sessionPct,
		{ anomaly: false, warmingUp, healthyColor: state.healthyColor },
		`${Math.round(sessionPct)}%`,
	);

	return `${iconPrefix}${dim(singleLabel)}${singleVal}${dim(sessionLabel)}${sessionVal}`;
}
