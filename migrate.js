const fs=require("fs"),path=require("path"),db=require("./db");
db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations(id TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
for(const f of fs.readdirSync(path.join(__dirname,"..","migrations")).filter(x=>x.endsWith(".sql")).sort()){
  if(db.prepare("SELECT 1 FROM schema_migrations WHERE id=?").get(f)) continue;
  db.transaction(()=>{db.exec(fs.readFileSync(path.join(__dirname,"..","migrations",f),"utf8"));db.prepare("INSERT INTO schema_migrations(id) VALUES(?)").run(f)})();
  console.log("Applied",f);
}
console.log("Migrations complete");
