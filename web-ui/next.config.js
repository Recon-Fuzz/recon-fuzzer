/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable React strict mode
  reactStrictMode: true,

  // Output as standalone for easier deployment
  output: 'standalone',

  // Disable image optimization for local use
  images: {
    unoptimized: true,
  },

  // Enable experimental features
  experimental: {
    // Optimize package imports
    optimizePackageImports: ['lucide-react', '@xyflow/react'],
  },

  // Environment variables to expose to the browser
  env: {
    NEXT_PUBLIC_WS_PORT: process.env.NEXT_PUBLIC_WS_PORT || '4444',
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL || '',
  },

  // Webpack configuration
  webpack: (config, { isServer }) => {
    // Don't bundle evmole on server side (WASM loaded client-side only)
    if (isServer) {
      config.externals = config.externals || [];
      config.externals.push('evmole');
    }

    return config;
  },
}

module.exports = nextConfig
