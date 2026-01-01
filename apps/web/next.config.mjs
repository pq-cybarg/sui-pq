/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: [
    '@sui-gen/sdk-core',
    '@sui-gen/wallet-kit',
    '@sui-gen/walrus-client',
    '@sui-gen/seal-client',
    '@sui-gen/lumiwave',
    '@sui-gen/zk-login',
  ],
  experimental: {
    optimizePackageImports: ['@mysten/sui', '@mysten/dapp-kit'],
  },
};

export default nextConfig;
