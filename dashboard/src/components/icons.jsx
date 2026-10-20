import React from "react";

const base = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true };
const I = (children) => (props) => <svg {...base} {...props}>{children}</svg>;

export const IconShield = I(<><path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.4-7.5 9.5-4.4-1.1-7.5-4.9-7.5-9.5V6L12 3z" /><path d="M9.5 12.2l1.9 1.9 3.3-3.6" /></>);
export const IconScan = I(<><path d="M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3" /><path d="M4 12h16" /></>);
export const IconSearch = I(<><circle cx="11" cy="11" r="6.5" /><path d="M16 16l4.5 4.5" /></>);
export const IconBook = I(<><path d="M5 4.5A1.5 1.5 0 016.5 3H19v15H6.5A1.5 1.5 0 005 19.5v-15z" /><path d="M5 19.5A1.5 1.5 0 006.5 21H19v-3" /></>);
export const IconChart = I(<><path d="M4 20V10M10 20V4M16 20v-7M22 20H2" /></>);
export const IconGear = I(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z" /></>);
export const IconSun = I(<><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>);
export const IconMoon = I(<path d="M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z" />);
export const IconLink = I(<><path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1" /><path d="M14 10a4 4 0 00-5.7 0l-3 3A4 4 0 0011 18.7l1-1" /></>);
export const IconCheck = I(<path d="M5 12.5l4.5 4.5L19 7.5" />);
export const IconCopy = I(<><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V6a2 2 0 012-2h9" /></>);
export const IconWrench = I(<path d="M14.7 6.3a4 4 0 005 5L20 14l-6 6-3-3 6-6-.3-.3a4 4 0 00-2.9-4.4zM9 21l-6 0 0-6 5-5" />);
export const IconDownload = I(<><path d="M12 4v11M7.5 11L12 15.5 16.5 11M5 20h14" /></>);
export const IconLayers = I(<><path d="M12 3l9 5-9 5-9-5 9-5z" /><path d="M3 13l9 5 9-5" /></>);
export const IconBolt = I(<path d="M13 3L5 14h6l-1 7 8-11h-6l1-7z" />);
export const IconBrain = I(<><path d="M9 4a3 3 0 00-3 3 3 3 0 00-2 5 3 3 0 002 5 3 3 0 003 3V4z" /><path d="M15 4a3 3 0 013 3 3 3 0 012 5 3 3 0 01-2 5 3 3 0 01-3 3V4z" /></>);
export const IconAlert = I(<><path d="M12 3l10 18H2L12 3z" /><path d="M12 10v5M12 18v.5" /></>);
