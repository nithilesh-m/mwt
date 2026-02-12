const fs = require("fs");

function log(message) {
  fs.appendFileSync(
    "app.log",
    `${new Date().toISOString()} ${message}\n`
  );
}

module.exports = log;
