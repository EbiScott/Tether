import { defineConfig } from "vitest/config";

/**
 * The source uses NodeNext ESM, so intra-package imports carry a `.js` extension (required for the
 * compiled output). This tiny resolver maps those `./x.js` specifiers back to `./x.ts` when running
 * the TypeScript sources directly under Vitest.
 */
export default defineConfig({
  plugins: [
    {
      name: "js-to-ts-resolver",
      enforce: "pre",
      async resolveId(source, importer) {
        if (importer && source.startsWith(".") && source.endsWith(".js")) {
          const resolved = await this.resolve(source.slice(0, -3) + ".ts", importer, {
            skipSelf: true,
          });
          if (resolved) return resolved;
        }
        return null;
      },
    },
  ],
  test: {
    include: ["tests/**/*.test.ts"],
  },
});
