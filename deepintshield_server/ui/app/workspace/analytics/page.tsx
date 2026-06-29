"use client";

// Analytics is the "glimpse of premium" surface: it reuses the full
// dashboard charts/tabs (usage, cost, latency, provider, model graphs)
// so the OSS portal keeps the same rich analytics UX without duplicating
// the data-fetching logic.
export { default } from "../dashboard/page";
