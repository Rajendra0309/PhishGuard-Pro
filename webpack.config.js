const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const webpack = require('webpack');
const dotenv = require('dotenv');
const fs = require('fs');

const env = dotenv.parse(fs.readFileSync('.env'));
const envKeys = Object.keys(env).reduce((prev, next) => {
  prev[`process.env.${next}`] = JSON.stringify(env[next]);
  return prev;
}, {});

module.exports = {
  entry: {
    popup: './popup.js',
    content: './content.js',
    history: './history.js'
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist')
  },
  mode: 'production',
  plugins: [
    new webpack.DefinePlugin(envKeys),
    new CopyPlugin({
      patterns: [
        { from: 'manifest.json', to: 'manifest.json' },
        { from: 'popup.html', to: 'popup.html' },
        { from: 'history.html', to: 'history.html' },
        { from: 'popup.css', to: 'popup.css' },
        { from: 'images', to: 'images' },
        { 
          from: 'background.js',
          to: 'background.js',
          transform(content) {
            let modifiedContent = content.toString();
            Object.keys(env).forEach(key => {
              modifiedContent = modifiedContent.replace(
                new RegExp(`process.env.${key}`, 'g'), 
                JSON.stringify(env[key])
              );
            });
            return modifiedContent;
          }
        }
      ],
    }),
  ],
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      }
    ]
  }
};
