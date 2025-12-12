<div align="center" style="padding-top: 5px">

<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/img/logo_nav.png" width="300" height="300"/>

## Margie and Rj Egg Store
*Fresh Eggs Daily!*

**Margie & RJ Egg Store** *is a family-run supplier offering fresh, carefully handled eggs for households and small businesses. We focus on consistent quality, prompt pickup or delivery, and honest, community-centered service.*

</div>

## Pre-requites

- *Node.js (LTS recommended)*
- *XAMPP* (Apache + MySQL/MariaDB)
- *Visual Studio Code or another IDE that has an integrated terminal*

## How to Run and Execute the File

**Verify Node js**
```bash
# check Node and npm
node -v
npm -v
```
- *If not installed, download and install from `https://nodejs.org/` (choose LTS)

## Start XAMPP and Open PhpMyAdmin

- *Open XAMPP Control Panel.*
- *Start Apache and MySQL.*
- *Click Admin next to MySQL to open phpMyAdmin.*

## Create Database
- *In PhpMyAdmin, create a database*
```bash
CREATE DATABASE egg_trading;
```

## Create Tables 
- *With `egg_trading` selected, open the SQL tab and run the following schema.*
```bash
CREATE TABLE users (
  id INT(11) NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) COLLATE utf8_general_ci NOT NULL,
  email VARCHAR(100) COLLATE utf8_general_ci NOT NULL,
  password VARCHAR(255) COLLATE utf8_general_ci NOT NULL,
  google_id VARCHAR(255) COLLATE utf8_general_ci DEFAULT NULL,
  password_reset_token VARCHAR(255) COLLATE utf8_general_ci DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  otp VARCHAR(6) COLLATE utf8_general_ci DEFAULT NULL,
  otp_expiry BIGINT(20) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TABLE IF NOT EXISTS orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  total_amount DECIMAL(10,2) NOT NULL,
  pickup_date DATE NOT NULL,
  pickup_time TIME NOT NULL,
  name VARCHAR(100) NOT NULL,
  phone VARCHAR(30) NOT NULL,
  address TEXT NOT NULL,
  notes TEXT,
  status ENUM('placed','cancelled') DEFAULT 'placed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS order_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_id INT NOT NULL,
  product_name VARCHAR(100) NOT NULL,
  size VARCHAR(50) NOT NULL,
  price DECIMAL(10,2) NOT NULL,
  quantity INT NOT NULL,
  subtotal DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE TABLE inventory (
  id INT(11) NOT NULL AUTO_INCREMENT,
  product_name VARCHAR(150) NOT NULL,
  sku VARCHAR(100) DEFAULT NULL,
  size VARCHAR(50) DEFAULT NULL,
  price DECIMAL(10,2) NOT NULL,
  stock INT(11) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE egg_orders (
  id INT(11) NOT NULL AUTO_INCREMENT,
  order_date DATE DEFAULT NULL,
  firstname VARCHAR(100) DEFAULT NULL,
  lastname VARCHAR(100) DEFAULT NULL,
  address VARCHAR(255) DEFAULT NULL,
  item VARCHAR(100) DEFAULT NULL,
  quantity INT(11) DEFAULT NULL,
  amount DECIMAL(10,2) DEFAULT NULL,
  si INT(11) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

## Open Projects and Install Dependencies

- *Open the project folder in Visual Studio Code.*
```bash
# from project root
code .
```

- *Install Node dependencies:*
```bash
npm install
```

## Run the Server

```bash
# start the server (example entry point)
node server.js
```
- *If package.json includes a start script, you can use:*
```bash
npm start
```
- *After the server starts the terminal will print a host URL such as `http://localhost:3000.` Click the link or open it in your browser.*

## Quick Commands Summary
```bash
# verify node/npm
node -v
npm -v

# install deps
npm install

# run server
node server.js
# or
npm start
```

## Troubleshooting
- **Port in Use** - Change the port in `server.js` or stop the process using that port.
- **Database connection errors** - Ensure MySQL is running in XAMPP. Verify DB credentials in `.env` or server config. Confirm `egg_trading` exists and tables were created.
- **Static assets 404** - Confirm `server.js` serves static files from the correct folder (for example `public`).

<div align="center" style="padding-top: 5px">
  
## User Interface of the Website

## Log-In Page
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Login_1.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Login_2.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Login_3.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Login_4.png" width="1000" height="1000"/>

## Log-In Page - Sign Up
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Sign_Up.png" width="1000" height="1000"/>

## Log-In Page - Forgot Password
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Forgot_Pass.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Verify_OTP.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Reset_Pass.png" width="1000" height="1000"/>

## Contact Us
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Contact_Us.png" width="1000" height="1000"/>

## Ordering Page
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Ordering_Page.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Ordering_Page2.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Ordering_Page_PrintReceipt.png" width="1000" height="1000"/>

## Admin's Console - Dashboard
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Admin's_Console.png" width="1000" height="1000"/>

## Admin's Console - Orders
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Admin's_Console2.png" width="1000" height="1000"/>

## Admin's Console - Inventory
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Admin's_Console3.png" width="1000" height="1000"/>

## Admin's Console - Reports
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Admin's_Console4.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Admin's_Console5.png" width="1000" height="1000"/>
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Admin's_Console6.png" width="1000" height="1000"/>

## Admin's Console - Users
<img src="https://github.com/wilxyz/FINALMargieandRjEggOrderSystem/blob/main/UI%20screenshots/Admin's_Console7.png" width="1000" height="1000"/>

</div>
