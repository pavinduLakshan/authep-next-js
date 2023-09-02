import React, { useEffect } from 'react';
import { BasicAuth } from '../components/login/basic-auth';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations'

export async function getStaticProps({ locale }) {
  return {
    props: {
      ...(await serverSideTranslations(locale, [
        'common',
        'footer',
      ])),
      // Will be passed to the page component as props
    },
  }
}

const Login = () => {

    return (
        <div>
          <p>Sign In</p> 
          <BasicAuth /> 
        </div>
    );
};

export default Login;
