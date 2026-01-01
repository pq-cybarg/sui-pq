'use client';
import { setComplete, useProgress } from '@/lib/progress';
import { SECTIONS, nextOf, prevOf } from '@/lib/sections';
import Link from 'next/link';

export function Pager({ slug }: { slug: string }) {
  const prev = prevOf(slug);
  const next = nextOf(slug);
  const completed = useProgress();
  const key = slug || 'welcome';
  const isDone = Boolean(completed[key]);

  return (
    <>
      <div className="mark-complete">
        <button
          type="button"
          className={isDone ? 'ghost' : 'primary'}
          onClick={() => setComplete(slug, !isDone)}
        >
          {isDone ? '✓ marked complete — click to undo' : 'Mark this section complete'}
        </button>
      </div>
      <div className="pager">
        {prev ? (
          <Link href={`/${prev.slug}`}>
            <div className="dir">← {SECTIONS.indexOf(prev) === 0 ? 'home' : 'previous'}</div>
            <div>{prev.title}</div>
          </Link>
        ) : (
          <span className="disabled" />
        )}
        {next ? (
          <Link href={`/${next.slug}`} style={{ textAlign: 'right' }}>
            <div className="dir">next →</div>
            <div>{next.title}</div>
          </Link>
        ) : (
          <span className="disabled" />
        )}
      </div>
    </>
  );
}
