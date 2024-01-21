const UserSchema = require('../model/UserSchema');
const bcrypt = require('bcrypt');
const jsonWebToken = require('jsonwebtoken');

const signup = async (req, resp) => {
    //async use for wait to to signup method. After finish signup other method will trigger
    UserSchema.findOne({ username: req.body.username }).then((result) => {
        if (result == null) {
            bcrypt.hash(req.body.password, 10, function (err, hash) {
                if (err) {
                    return resp.status(500).json({ message: "Something went wrong!" });
                }
                const user = new UserSchema({
                    username: req.body.username,
                    fullName: req.body.fullName,
                    password: hash
                });
                user.save().then(savedData => {
                    resp.status(201).json({ message: "User was saved!" });
                }).catch(error => {
                    resp.status(500).json(error);
                });
            });
        } else {
            resp.status(409).json({ message: "Username already exists!" });
        }
    }).catch(error => {
        resp.status(500).json(error);
    });
};

const login = async (req, resp) => {
    UserSchema.findOne({ username: req.body.username }).then((selectedUser) => {
        if (selectedUser == null) {
            return resp.status(404).json({ message: "Username not found!" });
        } else {
            bcrypt.compare(req.body.password, selectedUser.password, function (err, result) {
                if (err) {
                    return resp.status(500).json(error);
                }

                if (selectedUser) {

                    const expiresIn = 3600;
                    const token = jsonWebToken.sign({ 'username': selectedUser.username }, process.env.SECRET_KEY, { expiresIn });

                    resp.setHeader('Authorization', `Bearer ${token}`);

                    return resp.status(200).json({ message: 'Check the headers' });
                } else {
                    return resp.status(401).json({ message: 'Unauthorized. Password incorrect!' });
                }
            });
        }
    }).catch(error => {
        resp.status(500).json(error);
    });
}

module.exports = {
    signup,
    login
}