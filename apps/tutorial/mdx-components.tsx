import type { MDXComponents } from 'mdx/types';

/**
 * Next 15 MDX uses this file at the project root to merge custom components
 * into the MDX renderer. Keep it minimal here — page MDX imports its own
 * interactive components explicitly.
 */
export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    ...components,
  };
}
