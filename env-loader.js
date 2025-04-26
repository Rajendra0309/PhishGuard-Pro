
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

const envFile = path.resolve(__dirname, '.env');
const envConfig = dotenv.parse(fs.readFileSync(envFile));

let backgroundJsPath = path.resolve(__dirname, 'background.js');
let backgroundJs = fs.readFileSync(backgroundJsPath, 'utf8');

Object.keys(envConfig).forEach(key => {
  const placeholder = `process.env.${key}`;
  const value = JSON.stringify(envConfig[key]);
  backgroundJs = backgroundJs.replace(new RegExp(placeholder, 'g'), value);
});

const distDir = path.resolve(__dirname, 'dist');
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir);
}

fs.writeFileSync(path.resolve(distDir, 'background.js'), backgroundJs);

console.log('Environment variables injected into background.js');
