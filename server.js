const express = require('express');
const app = express();
const client = require('./db');
const path = require('path');
const { time } = require('console');

const PORT = process.env.PORT || 3000;


let ipLoginAttempts = {};

let ipTimeouts = {};

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// Parse URL-encoded form data (for HTML form POSTs) and JSON bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/', (req, res) => {
    // Render index with defaults so template can show empty state
    res.render('index', { results: undefined, q: '', vulnerable: false, executedQuery: null, error: null });
});

// Start the server after routes/middleware are configured
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});



/*app.get('/users', async (req, res) => {
    try {
        const result = await client.query('SELECT * FROM users;');
        res.json(result.rows);
    } catch (err) {
        console.error("Error executing query", err.stack);
        res.status(500).send("Internal Server Error");
    }
});*/

app.post('/users', async (req, res) => {
    const q = req.body.q || '';
    const vulnerable = req.body.vulnerable ? true : false;


    try {
        let result;
        let executedQuery = null;

        if (!q) {
            
            executedQuery = 'SELECT id, username FROM users;';
            result = await client.query('SELECT * FROM users;');
        } else if (vulnerable) {
            
            executedQuery = `SELECT userid,username FROM users WHERE username = '${q}';`;
            result = await client.query(executedQuery);
        } else {
            
            executedQuery = 'SELECT userid,username FROM users WHERE username = $1';
            result = await client.query(executedQuery, [q]);
        }

        res.render('index', { results: result.rows, q, vulnerable, executedQuery, error: null });
    } catch (err) {
        console.error('Error executing query', err.stack || err);
        res.render('index', { results: [], q, vulnerable, executedQuery: null, error: err.message || String(err) });
    }
});

app.post('/login', (req, res) => {
    // Use body fields for POST and a clearer name to avoid temporal-dead-zone issues
    const authVulnerable = req.body.authVulnerable ? true : false;
    const username = req.body.username || '';
    const password = req.body.password || '';
    let mess = "";



    if (!authVulnerable) {
        if (ipLoginAttempts[req.ip] && ipLoginAttempts[req.ip] >= 5) {
            if (Date.now() > ipTimeouts[req.ip]) {
                ipLoginAttempts[req.ip] = 0;
                ipTimeouts[req.ip] = null;
            }else{
            console.log(ipLoginAttempts[req.ip]);
            mess = "Previše neuspješnih pokušaja prijave. Pokušajte ponovo za " + Math.ceil((ipTimeouts[req.ip] - Date.now()) / 1000) + " sekundi.";
            return res.render('index', { authRes: mess, authVulnerable });
            }
        }
    }


    if (username === 'auth-admin' && password === 'MyPassword123!') {
        mess = "Uspješna prijava.";
        return res.render('index', { authRes: mess, authVulnerable });
    } else {
        if (authVulnerable) {
            
            if (username !== 'auth-admin') {
                mess = mess + "Pogrešno korisničko ime. ";
            }
            if (password !== 'MyPassword123!') {
                mess = mess + "Pogrešna lozinka. ";
            }
        } else {
            ipLoginAttempts[req.ip] = (ipLoginAttempts[req.ip] || 0) + 1;
            console.log(ipLoginAttempts[req.ip]);
            if(ipLoginAttempts[req.ip] == 5) {
                ipTimeouts[req.ip]=Date.now() + 5*60*1000; // 5 minutes lockout
            }
            mess = "Neispravno korisničko ime ili lozinka.\n Preostali pokušaji prijave: " + (5 - ipLoginAttempts[req.ip]);
        }
        return res.render('index', { authRes: mess, authVulnerable });
    }
});

app.get('/pass', (req, res) => {
    //serve the passwords.txt file
    res.download(path.join(__dirname, 'passwords.txt'));
});

app.get('/usersList', (req, res) => {
    //serve the users.txt file
    res.download(path.join(__dirname, 'users.txt'));
});
