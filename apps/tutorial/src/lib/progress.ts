'use client';
import { useEffect, useState } from 'react';

const KEY = 'tutorial-completed-v1';
const EVENT = 'sui-gen:progress';

export type Progress = Record<string, boolean>;

function read(): Progress {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Progress) : {};
  } catch {
    return {};
  }
}

function write(p: Progress): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(p));
    window.dispatchEvent(new CustomEvent(EVENT));
  } catch {}
}

export function isComplete(slug: string): boolean {
  return Boolean(read()[slug || 'welcome']);
}

export function toggleSection(slug: string): void {
  const key = slug || 'welcome';
  const p = read();
  if (p[key]) delete p[key];
  else p[key] = true;
  write(p);
}

export function setComplete(slug: string, value: boolean): void {
  const key = slug || 'welcome';
  const p = read();
  if (value) p[key] = true;
  else delete p[key];
  write(p);
}

export function clearAll(): void {
  write({});
}

/**
 * Subscribes to progress changes from anywhere — same-tab toggles AND
 * cross-tab via the native `storage` event.
 */
export function useProgress(): Progress {
  const [progress, setProgress] = useState<Progress>({});

  useEffect(() => {
    setProgress(read());
    const refresh = () => setProgress(read());
    window.addEventListener(EVENT, refresh);
    window.addEventListener('storage', (e) => {
      if (e.key === KEY) refresh();
    });
    return () => {
      window.removeEventListener(EVENT, refresh);
    };
  }, []);

  return progress;
}
