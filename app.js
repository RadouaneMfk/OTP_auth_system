import { configDotenv } from "dotenv";
import express from "express";
import nodemailer from "nodemailer"
import session from "express-session";
import path from "path";
import expressLayouts from "express-ejs-layouts";
import crypto from "crypto";

configDotenv();

const PORT = process.env.PORT || 3000

const app = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(expressLayouts);
app.set("view engine", "ejs");

function isAuthenticate(req, res, next) {
	if (req.session.isAuthenticated)
		return next();
	res.redirect("/login");
}

const transporter = nodemailer.createTransport({
	service: "gmail",
	auth: {
		user: process.env.EMAIL_USER,
		pass: process.env.EMAIL_PASS,
	},
})

app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: false,
	saveUninitialized: true,
	cookie: {
		secure: false ,
		maxAge: 2 * 24 * 60 * 60 * 1000,
	},
}))

app.get('/', (req, res) => {
	res.render("index", {title: "Home- OTP auth system"});
})

app.get('/how-it-works', (req, res) => {
	res.render("how-it-works", {title: "how-it-works- OTP auth system"});
})

app.get('/login', (req, res) => {
	res.render("login", {title: "login- OTP auth system"});
})

app.post('/send-otp', async (req, res) => {
	try {
		const {email} = req.body;
		req.session.otpAttempts = 0;

		const otp = Math.floor(100000 + Math.random() * 900000);
		const hashedOtp = crypto.createHash("sha256").update(String(otp)).digest("hex");
		req.session.otp = hashedOtp;
		req.session.email = email;
		req.session.otpExpiry = Date.now() + 5 * 60 * 1000;
		await transporter.sendMail({
			from: process.env.EMAIL_USER,
			to: email,
			subject: "your OTP for login",
			text: `your OTP is ${otp}, this will expire after 5 minutes!`,
		})
		res.render("verify-otp", {title: "verify-otp- OTP auth system", email: email, error: null});
	} catch (error) {
		console.log(error);
		res.render("login", {title: "login- OTP auth system", email: email, error: null});
	}
})

app.post('/verify-otp', async (req, res) => {
	try {
		const {otp} = req.body;
		req.session.otpAttempts = (req.session.otpAttempts || 0) + 1;
		if (req.session.otpAttempts > 5) {
			req.session.destroy();
			return res.render("login", {title: "login- OTP auth system", error: 'To many attempts, try again later'});
		}

		const hashedOtp = crypto.createHash("sha256").update(String(otp)).digest("hex");
		if (!req.session.otp || !req.session.otpExpiry) {
			return res.render('verify-otp', {title: 'verify-otp- OTP auth system',
				email: req.session.email,
				error: 'otp session expired, please try again',
			})
		}
		if (Date.now() > req.session.otpExpiry) {
			return res.render('verify-otp', {title: 'verify-otp- OTP auth system',
				email: req.session.email,
				error: 'OTP has expired, please request a new one',
			})
		}
		if (hashedOtp !== req.session.otp) {
			return res.render('verify-otp', {
				title: 'verify-otp- OTP auth system',
				email: req.session.email,
				error: 'Invalid OTP. please try again',
			})
		}
		const email = req.session.email;
		req.session.regenerate((err) => {
			if (err) {
				console.log(err);
				res.redirect("login", {title: "login- OTP auth system"});
			}
			delete req.session.otp;
			delete req.session.otpAttempts;
			delete req.session.otpExpiry;
			req.session.email = email;
			req.session.isAuthenticated = true;
			return res.redirect('/dashboard');
		})

	} catch (error) {
		return res.render('verify-otp', {
			title: 'verify-otp- OTP auth system',
			email: req.session.email,
			error: 'Something went wrong. please try again',
		})
	}
})

app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect("/");
})

app.get("/dashboard", isAuthenticate, (req, res) => {
	return res.render("dashboard", {title: "dashboard- OTP auth system", email: req.session.email});
})

app.listen(PORT, () => {
	console.log(`server is running at http://localhost:${PORT}`);
});
