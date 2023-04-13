const Users = require('../models/userModel')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const userCtrl = {
  register: async (req, res) => {
    try {
      const {name, email, password} = req.body;

      const user = await Users.findOne({email})
      if (user) return res.status(400).json({msg: "E-mail уже существует"})

      if (password.length < 6)
        return res.status(400).json({msg: 'Пароль должен быти длиннее 6 символов'})
        
        //шифрование пароля
        const passwordHash = await bcrypt.hash(password, 10)
        const newUser = new Users({
          name, email, password: passwordHash
        })

        //сохраняем пользака
        await newUser.save()
        
        //вебтокен аутентификации
        const accesstoken = createAccessToken({id: newUser._id})
        const refreshtoken = createRefreshToken({id: newUser._id})

        res.cookie('refreshtoken', refreshtoken, {
          httpOnly: true,
          path: '/user/refresh_token',
        })

        res.json({accesstoken})
        //res.json({msg: "Успешная регистрация!"})
    
      } catch (error) {
        return res.status(500).json({msg: error.message})
    }
  },
  login: async (req,res) => {
    try {
      const {email, password} = req.body;

      const user = await Users.findOne({email})
      if(!user) return res.status(400).json({msg: "User not found"})

      const isMatch = await bcrypt.compare(password, user.password)
      if(!isMatch) return res.status(400).json({msg: "Неверный пароль"})

      //если все правильно, создать токен
      const accesstoken = createAccessToken({id: user._id})
      const refreshtoken = createRefreshToken({id: user._id})

      res.cookie('refreshtoken', refreshtoken, {
        httpOnly: true,
        path: '/user/refresh_token',
      })

      res.json({accesstoken})
    } catch (err) {
        return res.status(500).json({msg: err.message})
    }
  },
  logout: async (req, res) => {
    try {
      res.clearCookie('refreshtoken', {path: '/user/refresh_token'})
      return res.json({msg: "Успешный выход"})
    } catch (error) {
      return res.status(500).json({msg: err.message})
    }
  },
  refreshToken: (req,res) => {
    try {
      const rf_token = req.cookies.refreshtoken;
      if(!rf_token) return res.status(400).json({msg: "Please login or register"})

      jwt.verify(rf_token, process.env.REFRESH_TOKEN_SECRET, (err, user) =>{
        if(err) return res.status(400).json({msg: "Please login or register2323"})

        const accesstoken = createAccessToken({id: user.id})

        res.json({accesstoken})
      })

      //res.json({rf_token})
    } catch (err) {
      return res.status(500).json({msg: err.message})
    }
    

    
  },
  getUser: async (req, res) => {
    try {
      const user = await Users.findById(req.user.id).select('-password')
      if(!user) return res.status(500).json({msg: "Пользователь не существует"})
      res.json(user)
    } catch (err) {
      return res.status(500).json({msg: err.message})
    }
  }
}

const createAccessToken = (user) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1d'})
}
const createRefreshToken = (user) => {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '7d'})
}

module.exports = userCtrl