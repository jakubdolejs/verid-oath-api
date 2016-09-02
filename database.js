const nconf = require('nconf');
nconf.add('db', { "type":"file", "file": __dirname+'/config.json' });
nconf.load();

const nano = require('nano')(nconf.get("env:database:url"));
module.exports = nano.db.use(nconf.get("env:database:name"));