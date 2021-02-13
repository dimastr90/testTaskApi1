//Imports
const express = require('express');
const mongoose = require('mongoose');
const jsonwebtoken = require('jsonwebtoken');
const {v4: uuid} = require('uuid');
const User = require('./models/User');
const bcrypt = require('bcrypt');
//end imports


//Service area
const app = express();
const PORT = 8080;
const JWT_SECRET = 'somesecretkey';
const BCRYPT_SALT = 12;

//End service area


//EndPoints
app.post('/login/', async (req, res) => {
    try {
        const {username, password} = req.body;
        const user = await User.findOne({username});

        if (user) {
            bcrypt.compare(password, user.password, (err, result) => {
                    if (result) {
                        const accessToken = jsonwebtoken.sign({
                            uid: username,
                            jwtid: uuid()
                        }, JWT_SECRET, {expiresIn: '1h'});
                        res.status(201).json({token: accessToken, error: null});
                    } else {
                        res.status(401).json({error: 'Введите правильные имя пользователя/пароль', token: null});
                    }
                }
            )
        } else {
            res.status(401).json({error: 'Введите правильные имя пользователя/пароль', token: null});
        }
    } catch (e) {
        console.warn(e.message);
        res.status(500).json({message: e.message});
    }
});


app.post('/register/', async (req, res) => {
    try {
        const {username, password} = req.body;
        const user = await User.findOne({username});

        if (user) {
            res.status(401).json({message: 'Пользователь с таким именем уже зарегистрирован'});
        } else {
            bcrypt.hash(password, BCRYPT_SALT, async (error, hash) => {
                const newUser = new User({username, password: hash});
                await newUser.save();
                res.status(200).json({message: 'Пользователь успешно зарегистрирован'});
            });
        }
    } catch (e) {
        console.warn(e.message);
        res.status(500).json({message: e.message});
    }
});


app.get('/about/', async (req, res) => {
    try {
        if(!req.headers.bearer) {
            res.status(401).json({message: 'Пользователь не авторизован'});
        }

        let token = null;
        try {
            token = await jsonwebtoken.verify(req.headers.bearer, JWT_SECRET);
        } catch (e) {
            res.status(400).json({message: 'Не удалось получить информацию о пользователе'});
        }


        if(token){
            const userId = token.uid;
            const user = await User.findOne({username: userId});
            res.status(200).json({id: user._id, username: user.username});
        }

    } catch (e) {
        console.warn(e.message);
        res.status(500).json({message: e.message});
    }
});


//End endpoints


//Mongo
async function start() {
    try {
        await mongoose.connect('mongodb+srv://admin:pass@cluster0.mrxij.mongodb.net/users?retryWrites=true&w=majority', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true,
        });
    } catch (e) {
        console.log("Server Error", e.message);
        process.exit(1);
    }
}

start();

//End mongo

app.listen(PORT, () => console.log(`Server is started on port ${PORT}`));