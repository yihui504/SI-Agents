#!/usr/bin/env bun
import { main } from "../src/cli/main.ts"

main(process.argv.slice(2))
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err)
    process.exit(1)
  })
