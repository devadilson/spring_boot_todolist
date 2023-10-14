package br.com.devadilson.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.devadilson.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    // Verificando Rotas
    var serveletPath = request.getServletPath();

    // Rotas não autenticadas
    if (serveletPath.startsWith("/tasks/")) {
      // Autenticação (usuário e senha)
      var authCheck = request.getHeader("Authorization");
      var authEncode = authCheck.substring("Basic".length()).trim();
      byte[] authDecode = Base64.getDecoder().decode(authEncode);
      var authString = new String(authDecode);
      System.out.println("Authorization");
      String[] credentials = authString.split(":");
      String username = credentials[0];
      String password = credentials[1];
      System.out.println(username);
      System.out.println(password);

      // Validar Usuário
      var user = userRepository.findByUsername(username);
      if (user == null) {
        response.sendError(401);
      } else {
        // Validar Senha
        var checkPassword = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
        if (checkPassword.verified) {
          request.setAttribute("idUser", user.getId());
          filterChain.doFilter(request, response);
        } else {
          response.sendError(401);
        }
      }
    } else {
      filterChain.doFilter(request, response);
    }

  }

}
