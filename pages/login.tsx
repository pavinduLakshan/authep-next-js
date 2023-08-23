import React, { useEffect } from 'react';
import { BasicAuth } from '../components/login/basic-auth';

const Login = () => {

    const params = new URLSearchParams(global?.window && window.location.search);

    return (
        <div>
          <p>Login</p> 
          <BasicAuth /> 
        </div>
    );
};

export default Login;
