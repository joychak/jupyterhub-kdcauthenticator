**KDC authenticator allows to authenticate the JuypterHub user using Kerberos protocol

#How to install, configure and run KDCAuthenticator

1. Install KDC Authenticator

 Run the following command at kdcauthenticator directory
 ```
 pip3 install -e kdcauthenticator
 ```

2. Configure JupyterHub for KDC Authenticator

 Add the following line to the jupyterHub config file
 ```
 c.JupyterHub.authenticator_class = 'kdcauthenticator.kdcauthenticator.KDCAuthenticator'
 ```
 Optionally you can add the following lines to create local system users
 ```
 c.LocalAuthenticator.add_user_cmd = ['adduser', '-m']
 c.LocalAuthenticator.create_system_users = True
 ```

3. The Service principle for JupyterHub authenticator is configured to "HTTP" but can be configured by -

 ```
 c.KDCAuthenticator.service_name = '<HTTP-Service-Principle>'
 ```

4. Run the JupyterHub command with Kerberos environment variables -

 ```
 KRB5_CONFIG=[Kerberos-config-path] KRB5_KTNAME=[HTTP-Service-Principle-Keytab-path] jupyterhub --ip=0.0.0.0 --port=8000 --no-ssl --config=[jupyterHub-config-file-path]
 ```





