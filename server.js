const mongoose = require('mongoose');

const express = require('express');

const path = require('path');
// importing the dotenv module to load environment variables from a .env file into process.env
require('dotenv').config();
const userRouter  = require('./routes/userRouter');

const authFunctions = require('./Controller/authFunctions');

//  setting mongoose to use strict query
mongoose.set('strictQuery', true);
//connecting to MongoDB using the connection string from environment variables
mongoose.connect(process.env.DB_CONNECT) 
    .then(()=> {
        console.log("MongoDB connected...") // log when successfully connected
    })
// creating express app
const app = express();
// setting the port to env variable or deafult to 3000
const PORT = process.env.PORT || 3000;
// this will parse incoming request bodies 
app.use(express.json());

app.use(express.urlencoded({ extended: true}));


app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html'}));

app.use('', userRouter);

app.post('/forgot-password', (req, res) => authFunctions.forgotPassword(req.body, res));
app.post('/reset-password', (req, res) => authFunctions.resetPassword(req.body, res));

app.post('/verify-2fa', (req, res) => authFunctions.verify2FA(req.body, res));
app.post('/resend-2fa', (req, res) => authFunctions.resend2FA(req.body, res));


app.listen(PORT, () => {
    console.log(`Server started on Port ${PORT}`);
    console.log(`Click here to access http://localhost:${PORT}`);
})