// Backward-compatible entry point; the portable suite uses only isolated temporary data.
import('./test_integration.mjs').catch(err => { console.error(err); process.exitCode = 1 })
