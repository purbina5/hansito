<?php
	// Include config file
	require_once 'config/config.php';


	// Define variables and initialize with empty values
	$username = $password = $confirm_password = "";

	$username_err = $password_err = $confirm_password_err = "";

	// Process submitted form data
	if ($_SERVER['REQUEST_METHOD'] === 'POST') {

		// Check if username is empty
		if (empty(trim($_POST['username']))) {
			$username_err = "Ingresa un nombre de usuario";

			// Check if username already exist
		} else {

			// Prepare a select statement
			$sql = 'SELECT id FROM users WHERE username = ?';

			if ($stmt = $mysql_db->prepare($sql)) {
				// Set parmater
				$param_username = trim($_POST['username']);

				// Bind param variable to prepares statement
				$stmt->bind_param('s', $param_username);

				// Attempt to execute statement
				if ($stmt->execute()) {
					
					// Store executed result
					$stmt->store_result();

					if ($stmt->num_rows == 1) {
						$username_err = 'Este nombre de usuario ya esta en uso';
					} else {
						$username = trim($_POST['username']);
					}
				} else {
					echo "Oops! ${$username}, ups algo fallo, intentalo de nuevo mas tarde";
				}

				// Close statement
				$stmt->close();
			} else {

				// Close db connction
				$mysql_db->close();
			}
		}

		// Validate password
	    if(empty(trim($_POST["password"]))){
	        $password_err = "Por favor ingresa una contraseña";     
	    } elseif(strlen(trim($_POST["password"])) < 6){
	        $password_err = "la contraseña debe de tener minimo 6 caracteres";
	    } else{
	        $password = trim($_POST["password"]);
	    }
    
	    // Validate confirm password
	    if(empty(trim($_POST["confirm_password"]))){
	        $confirm_password_err = "Por favor confirma la contraseña";     
	    } else{
	        $confirm_password = trim($_POST["confirm_password"]);
	        if(empty($password_err) && ($password != $confirm_password)){
	            $confirm_password_err = "Las contraseñas no coinciden";
	        }
	    }

	    // Check input error before inserting into database

	    if (empty($username_err) && empty($password_err) && empty($confirm_err)) {

	    	// Prepare insert statement
			$sql = 'INSERT INTO users (username, password) VALUES (?,?)';

			if ($stmt = $mysql_db->prepare($sql)) {

				// Set parmater
				$param_username = $username;
				$param_password = password_hash($password, PASSWORD_DEFAULT); // Created a password

				// Bind param variable to prepares statement
				$stmt->bind_param('ss', $param_username, $param_password);

				// Attempt to execute
				if ($stmt->execute()) {
					// Redirect to login page
					header('location: ./Index.php');
					// echo "Will  redirect to login page";
				} else {
					echo "Algo fallo, por favor intentalo de nuevo mas tarde";
				}

				// Close statement
				$stmt->close();	
			}

			// Close connection
			$mysql_db->close();
	    }
	}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Sign in</title>
	<link href="https://stackpath.bootstrapcdn.com/bootswatch/4.4.1/cosmo/bootstrap.min.css" rel="stylesheet" integrity="sha384-qdQEsAI45WFCO5QwXBelBe1rR9Nwiss4rGEqiszC+9olH1ScrLrMQr1KmDR964uZ" crossorigin="anonymous">
	<style>
        .wrapper{ 
        	width: 500px; 
        	padding: 20px; 
        }
        .wrapper h2 {text-align: center}
        .wrapper form .form-group span {color: red;}
	</style>
</head>
<body>
	<main>
		<section class="container wrapper">
			<h2 class="display-4 pt-3">Inicio de sesión</h2>
        	<p class="text-center">Por favor coloque sus credenciales</p>
        	<form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="POST">
        		<div class="form-group <?php (!empty($username_err))?'has_error':'';?>">
        			<label for="username">Nombre de usuario</label>
        			<input type="text" name="username" id="username" class="form-control" value="<?php echo $username ?>">
        			<span class="help-block"><?php echo $username_err;?></span>
        		</div>

        		<div class="form-group <?php (!empty($password_err))?'has_error':'';?>">
        			<label for="password">Contraseña</label>
        			<input type="password" name="password" id="password" class="form-control" value="<?php echo $password ?>">
        			<span class="help-block"><?php echo $password_err; ?></span>
        		</div>

        		<div class="form-group <?php (!empty($confirm_password_err))?'has_error':'';?>">
        			<label for="confirm_password">Confirmar contraseña</label>
        			<input type="password" name="confirm_password" id="confirm_password" class="form-control" value="<?php echo $confirm_password; ?>">
        			<span class="help-block"><?php echo $confirm_password_err;?></span>
        		</div>

        		<div class="form-group">
        			<input type="submit" class="btn btn-block btn-outline-success" value="Submit">
        			<input type="reset" class="btn btn-block btn-outline-primary" value="Reset">
        		</div>
        		<p>Ya tienes una cueta? <a href="Login.php">Inicia sesión aqui</a>.</p>
        	</form>
		</section>
	</main>
</body>
</html>