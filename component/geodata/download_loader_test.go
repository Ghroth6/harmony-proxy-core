package geodata_test

// Match the application's standard-loader registration without importing a
// geodata implementation from inside its own package and creating a cycle.
import _ "github.com/metacubex/mihomo/component/geodata/standard"
