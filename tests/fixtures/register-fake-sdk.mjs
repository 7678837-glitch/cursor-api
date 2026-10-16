// `node --import ./tests/fixtures/register-fake-sdk.mjs dist/index.js`
// redirects `@cursor/sdk` to the local fake for integration tests.
import { register } from "node:module";

register(
  "data:text/javascript," +
    encodeURIComponent(`
      const fake = ${JSON.stringify(new URL("./fake-cursor-sdk.mjs", import.meta.url).href)};
      export async function resolve(specifier, context, next) {
        if (specifier === "@cursor/sdk") return { url: fake, shortCircuit: true };
        return next(specifier, context);
      }
    `),
);
