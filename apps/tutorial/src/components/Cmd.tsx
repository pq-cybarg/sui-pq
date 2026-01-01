'use client';
import { useState } from 'react';

/** Inline shell-command block with copy-to-clipboard. */
export function Cmd({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);
  const text = String(children).trim();
  return (
    <div className="cmd">
      <span>{text}</span>
      <button
        type="button"
        className="copy"
        onClick={() => {
          navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
      >
        {copied ? 'copied' : 'copy'}
      </button>
    </div>
  );
}
