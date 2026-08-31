require("dotenv").config();const bcrypt=require("bcryptjs"),db=require("./db");require("./migrate");
const email=process.env.OWNER_EMAIL||"owner@example.com",password=process.env.OWNER_PASSWORD||"ChangeMe_12345";
if(!db.prepare("SELECT id FROM users WHERE email=?").get(email)){
  const publicId="TXG-"+require("crypto").randomBytes(6).toString("hex").toUpperCase();
  db.prepare("INSERT INTO users(public_id,username,email,phone_e164,password_hash,role) VALUES(?,?,?,?,?,'owner')")
    .run(publicId,"owner",email,"+10000000000",bcrypt.hashSync(password,12));
  console.log("Owner created:",email);
}else console.log("Owner already exists");
const defaults={upi_id:"skimran876@fam",qr_image_url:"",ads_text:"Welcome to TXG Gateway.",channel_url:"",alert_bot_enabled:"true",alert_chat_id:"5478832701",deposit_mode:"manual",withdraw_min:"1",withdraw_max:"100000"};
for(const [k,v] of Object.entries(defaults)) db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").run(k,v);
console.log("Seed complete");
