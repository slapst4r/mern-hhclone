require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const fileUpload = require('express-fileupload')
const cookieParser = require('cookie-parser')


const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(cors())
app.use(fileUpload({
  useTempFiles: true
}))

//routes
app.use('/user', require('./routes/userRouter.js'))
app.use('/api', require('./routes/categoryRouter.js'))




//Соединение с монгодб
const URI = process.env.MONGODB_URL

try {
  mongoose.connect(URI)
  console.log('conn succesful')
} catch (err) {
  console.log('connection error', err)
}


const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log('Server is running on port', PORT)
})