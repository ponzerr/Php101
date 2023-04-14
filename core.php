<?php
include "connection.php";
if (isset($_POST['btn_register']))
{
    $fullname = $_POST['fullname'];
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (isset($_POST['fullname']) || isset($_POST['username']) || isset($_POST['password']))
    {
        $password = password_hash($password, PASSWORD_DEFAULT);
        $sql = "INSERT INTO user (full_name, username, password) 
                  VALUES(?, ?, ?)"; 
        $stmt = mysqli_stmt_init($con);
        echo "success";
    }
    if(!mysqli_stmt_prepare($stmt, $sql)){
        echo "SQL Statement Failed.";
    } else {
        mysqli_stmt_bind_param($stmt, "sss", $fullname, $username, $password);
        mysqli_stmt_execute($stmt);
    }

}

if (isset($_POST['btn_login']))
{
    $username = $_POST['username'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM user WHERE username = ? ";
    $stmt = mysqli_stmt_init($con);

        if (!mysqli_stmt_prepare($stmt, $sql)){
            echo "Unknown Account..";
            return;
        } else {
            mysqli_stmt_bind_param($stmt, "s", $username);
            mysqli_stmt_execute($stmt);

            $result = mysqli_stmt_get_result($stmt);

            if(mysqli_num_rows($result) != NULL){
                $row = mysqli_fetch_assoc($result);

                $conpassword = $row['password'];

                if(password_verify($password, $conpassword) == TRUE){

                    $SESSION['signin_success'] = "signin_success";
                    $SESSION['id'] = $row ["id"];
                    $SESSION['full_name'] = $row ["full_name"];
                    $SESSION['username'] = $row ["username"];
                    $SESSION['password'] = $row ["password"];

                    header('location: dashboard.php');
                } else {
                    echo "Sorry you have entered invalid credentials";
                    return;
                }
            }

        }
        
    
}