package mobile.computing.ws1819.server;

import java.io.IOException;
import javax.swing.JOptionPane;
import com.sun.jersey.api.container.httpserver.HttpServerFactory;
import com.sun.net.httpserver.HttpServer;

public class StartRestServer {

	public static synchronized void main(String[] args) throws IllegalArgumentException, IOException {
		HttpServer server = HttpServerFactory.create("http://127.0.0.1:8080/api");
		server.start();
		JOptionPane.showMessageDialog(null, "Press OK to shutdown server.");
		server.stop(0);
	}

}
