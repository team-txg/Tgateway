const crypto=require("crypto"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken");
const SECRET=process.env.JWT_SECRET||"development-only-change-me";
const sha=x=>crypto.createHash("sha256").update(String(x)).digest("hex");
const otp=()=>String(crypto.randomInt(100000,1000000));
const token=()=>crypto.randomBytes(32).toString("hex");
const hashPassword=p=>bcrypt.hashSync(p,12);
const checkPassword=(p,h)=>bcrypt.compareSync(p,h);
const sign=u=>jwt.sign({sub:u.id,role:u.role,session:u.session_id},SECRET,{expiresIn:"2h"});
module.exports={sha,otp,token,hashPassword,checkPassword,sign};
