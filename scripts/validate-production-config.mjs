import { validateProductionEnvironment } from '../config/production-env.mjs';

const errors = validateProductionEnvironment(process.env);
if (process.env.NODE_ENV !== 'production') {
  console.log(JSON.stringify({ status: 'not-production-mode', valuesPrinted: false }));
} else if (errors.length) {
  console.error(JSON.stringify({ status: 'invalid', errors, valuesPrinted: false }, null, 2));
  process.exitCode = 1;
} else {
  console.log(JSON.stringify({ status: 'configuration-shape-valid', providerChecksRequired: true, valuesPrinted: false }));
}
