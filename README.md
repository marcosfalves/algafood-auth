<p align="center">
   <img src="http://img.shields.io/static/v1?label=STATUS&message=EM%20DESENVOLVIMENTO&color=RED&style=for-the-badge"/>
</p>

# algafood-auth
Essa aplicação é um Authorization Server para a REST API de delivery de comida AlgaFood desenvolvida durante o curso Especialista Spring REST (ESR) da Algaworks.

# ATENÇÃO
O projeto Spring Security OAuth 2 foi depreciado e contém várias dependências desatualizadas e com vulnerabilidades detectadas. Sendo assim, não é adequada sua utilização em ambiente de produção.

## Notas
O projeto *Spring Security OAuth* foi descontinuado e foi substituído pelo suporte OAuth2 fornecido pelo [Spring Security](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html) e [Spring Authorization Server](https://spring.io/projects/spring-authorization-server).

Porém durante a gravação do curso ainda não existia o suporte a criação de um Authorization server pela nova stack, pois o Spring tinha decidido não portar esse suporte para o novo projeto, conforme explicado [nessa nota](https://spring.io/blog/2019/11/14/spring-security-oauth-2-0-roadmap-update).

Portando foi utilizado a nova stack *Spring Security* para o Resource Server (API) e a antiga depreciada *Spring Security OAuth* para o Authorization Server.

Porém depois de feedbacks da comunidade o Spring decidiu portar o suporte a Authorization Server, criando assim o projeto [Spring Authorization Server](https://spring.io/projects/spring-authorization-server). No final do curso existe um módulo dedicado a fazer a atualização para o novo projeto.

## Desenvolvido com
* [Spring Framework](https://spring.io/projects/spring-framework)
* [Spring Security OAuth2](https://spring.io/projects/spring-security-oauth)
* [Spring Boot](https://spring.io/projects/spring-boot)

## Execução Local
### Pré-requisitos
- ⚫ [Git](https://git-scm.com/)
- ☕ [Java 17 ou superior](https://openjdk.org/projects/jdk/)
    - Sugestão: Utilizar SDKMan para instalar o java:
        - [Instalação do SDKMan](https://sdkman.io/install)
        - [Instalação do Java utilizando o SDKMan](https://sdkman.io/usage)

### Instruções

1. Clone o repositório
   ```sh
   git clone https://github.com/marcosfalves/algafood-auth.git
   ```
2. Abra em sua IDE preferida
3. Execute a aplicação em sua IDE
    - Iniciar o método main da classe [AuthApplication](./src/main/java/com/algaworks/algafood/auth/AuthApplication.java)