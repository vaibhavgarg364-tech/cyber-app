export default {
  testEnvironment: 'jsdom',
  roots: ['<rootDir>/src'],
  moduleFileExtensions: ['js', 'jsx', 'ts', 'tsx'],
  transform: {
    '^.+\\.tsx?$': ['@swc/jest', {
      jsc: {
        parser: { syntax: 'typescript', tsx: true },
        transform: { 
          react: { runtime: 'automatic' },
          optimizer: {
            globals: {
              vars: {
                "import.meta.env.VITE_BACKEND_API_URL": '"http://127.0.0.1:8000/api"'
              }
            }
          }
        },
      },
    }],
    '^.+\\.jsx?$': ['@swc/jest', {
      jsc: {
        parser: { syntax: 'ecmascript', jsx: true },
        transform: { 
          react: { runtime: 'automatic' },
          optimizer: {
            globals: {
              vars: {
                "import.meta.env.VITE_BACKEND_API_URL": '"http://127.0.0.1:8000/api"'
              }
            }
          }
        },
      },
    }],
  },
  setupFilesAfterEnv: ['<rootDir>/src/test/setupTests.js'],
  moduleNameMapper: {
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },
};
