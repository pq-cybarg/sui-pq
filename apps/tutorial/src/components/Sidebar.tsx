'use client';
import { clearAll, toggleSection, useProgress } from '@/lib/progress';
import { SECTIONS } from '@/lib/sections';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export function Sidebar() {
  const pathname = usePathname();
  const completed = useProgress();
  const here = pathname === '/' ? '' : pathname.replace(/^\//, '');

  const doneCount = SECTIONS.reduce((acc, s) => acc + (completed[s.slug || 'welcome'] ? 1 : 0), 0);

  function handleToggle(e: React.MouseEvent<HTMLButtonElement>, slug: string) {
    e.preventDefault();
    e.stopPropagation();
    toggleSection(slug);
  }

  function handleClear() {
    if (window.confirm('Clear all tutorial progress?')) clearAll();
  }

  return (
    <aside className="sidebar">
      <h1>
        <span className="dot" /> sui-gen tutorial
      </h1>
      <nav>
        {SECTIONS.map((s) => {
          const key = s.slug || 'welcome';
          const href = `/${s.slug}`;
          const active = s.slug === here;
          const done = Boolean(completed[key]);
          return (
            <div key={key} className={`nav-row ${active ? 'active' : ''}`}>
              <button
                type="button"
                className={`checkbox ${done ? 'done' : ''}`}
                aria-label={
                  done ? `Mark "${s.title}" as not complete` : `Mark "${s.title}" as complete`
                }
                title={done ? 'Mark as not complete' : 'Mark as complete'}
                onClick={(e) => handleToggle(e, s.slug)}
              >
                {done ? '✓' : ''}
              </button>
              <Link href={href} className={active ? 'active' : ''}>
                {s.title}
                <span className="sub">{s.subtitle}</span>
              </Link>
            </div>
          );
        })}
      </nav>
      <div className="foot">
        <p>
          <strong>
            {doneCount}/{SECTIONS.length}
          </strong>{' '}
          complete · ~{SECTIONS.reduce((acc, s) => acc + s.minutes, 0)} min total.
        </p>
        <p>Demos hit Sui testnet. Bring 0.1 SUI of gas (see step 1).</p>
        <p style={{ marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={handleClear}
            className="clear-progress"
            disabled={doneCount === 0}
          >
            Clear progress
          </button>
        </p>
        <p style={{ marginTop: '1rem' }}>
          <a href="https://github.com/MystenLabs/sui" target="_blank" rel="noreferrer">
            Sui ↗
          </a>
          {' · '}
          <a href="https://docs.wal.app" target="_blank" rel="noreferrer">
            Walrus ↗
          </a>
          {' · '}
          <a href="https://seal.mystenlabs.com" target="_blank" rel="noreferrer">
            Seal ↗
          </a>
        </p>
      </div>
    </aside>
  );
}
