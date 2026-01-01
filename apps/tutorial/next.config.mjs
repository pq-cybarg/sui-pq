import createMDX from '@next/mdx';

const withMDX = createMDX({
  extension: /\.mdx?$/,
});

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  pageExtensions: ['ts', 'tsx', 'js', 'jsx', 'md', 'mdx'],
  transpilePackages: [
    '@sui-gen/sdk-core',
    '@sui-gen/wallet-kit',
    '@sui-gen/walrus-client',
    '@sui-gen/seal-client',
    '@sui-gen/lumiwave',
  ],
  experimental: {
    mdxRs: false,
  },
};

export default withMDX(nextConfig);
