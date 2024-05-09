package controller;

import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.ArrayList;

import model.CartItem;
import model.CartModel;
import model.LoginModel;
import model.OrderDetail;
import model.OrderModel;
import model.PasswordEncryptionWithAes;
import model.ProductModel;
import model.UserModel;
import util.StringUtils;

public class DatabaseController {
	public Connection getConnection() throws SQLException, ClassNotFoundException {

		// Load the JDBC driver class specified by the StringUtils.DRIVER_NAME constant
		Class.forName(StringUtils.DRIVER_NAME);

		// Create a connection to the database using the provided credentials
		return DriverManager.getConnection(StringUtils.LOCALHOST_URL, StringUtils.LOCALHOST_USERNAME,
				StringUtils.LOCALHOST_PASSWORD);
	}

	public int registeruser(UserModel user) {

		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_REGISTER_USER);

			stmt.setString(1, user.getEmail());
			stmt.setString(2, user.getGender());
			stmt.setString(3, user.getAddress());
			stmt.setString(4, user.getphone());
			stmt.setDate(5, Date.valueOf(user.getDob()));
			stmt.setString(6, user.getUsername());
			stmt.setString(7, PasswordEncryptionWithAes.encrypt(user.getUsername(), user.getPassword()));
			stmt.setString(8, user.getRole());
			stmt.setString(9, user.getImagePath());

			int result = stmt.executeUpdate();

			if (result > 0) {
				return 1;
			} else {
				return 0;
			}

		} catch (ClassNotFoundException | SQLException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public LoginModel getuserLoginInfo(LoginModel loginModel) {
		try {
			PreparedStatement st = getConnection().prepareStatement(StringUtils.QUERY_CHECK_USER);

			st.setString(1, loginModel.getUsername());

			ResultSet result = st.executeQuery();

			if (result.next()) {
				int uid = result.getInt("userID");
				String userDb = result.getString(StringUtils.USERNAME);

				String encryptedPwd = result.getString(StringUtils.PASSHASH);

				String decryptedPwd = PasswordEncryptionWithAes.decrypt(encryptedPwd, userDb);

				String role = result.getString(StringUtils.ROLE);

				LoginModel loginResult = new LoginModel(userDb, decryptedPwd, role);
				loginResult.setUid(uid);
				return loginResult;

			} else {
				loginModel.setRole("NF");
				return loginModel;
			}

		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			loginModel.setRole("");
			return loginModel;
		}
	}

	public ArrayList<UserModel> getUsersInfo(String name) {

		ArrayList<UserModel> users = new ArrayList<UserModel>();

		if (name == null || name.equals("")) {
			name = "%%";
		} else {
			name = "%" + name + "%";
		}

		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_USERS);
			stmt.setString(1, name);
			ResultSet result = stmt.executeQuery();
			while (result.next()) {
				UserModel user = new UserModel();
				user.setUserID(result.getInt("userID"));
				user.setUsername(result.getString("username"));
				user.setEmail(result.getString("email"));
				user.setAddress(result.getString("address"));
				user.setDob(result.getDate("dob").toLocalDate());
				user.setGender(result.getString("gender"));
				user.setphone(result.getString("phone"));
				user.setPassword(result.getString("passhash"));
				user.setRole(result.getString("role"));
				users.add(user);
			}
			return users;
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return users;
		}
	}

	public UserModel getUserInfo(int uid) {
		UserModel user = new UserModel();
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_USER);
			stmt.setInt(1, uid);
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				user.setUserID(uid);
				user.setUsername(result.getString("username"));
				user.setEmail(result.getString("email"));
				user.setphone(result.getString("phone"));
				user.setDob(result.getDate("dob").toLocalDate());
				user.setAddress(result.getString("address"));
				user.setGender(result.getString("gender"));
				user.setImagePath(result.getString("imagePath"));
				user.setRole(result.getString("role"));
				user.setPassword(result.getString("passhash"));
				return user;
			} else {
				return user;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return user;
		}
	}

	public int UpdateUser(UserModel user) {
		try {

			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_UPDATE_USER);
			stmt.setString(1, user.getEmail());
			stmt.setString(2, user.getGender());
			stmt.setString(3, user.getAddress());
			stmt.setString(4, user.getphone());
			stmt.setDate(5, Date.valueOf(user.getDob()));
			stmt.setString(6, user.getUsername());
			stmt.setString(7, PasswordEncryptionWithAes.encrypt(user.getUsername(), user.getPassword()));
			stmt.setString(8, user.getRole());
			stmt.setString(9, user.getImagePath());
			stmt.setInt(10, user.getUserID());

			int result = stmt.executeUpdate();

			if (result > 0) {
				return 1;
			} else {
				return 0;
			}

		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int UpdatePass(UserModel user) {
		try {

			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_UPDATE_PASS);
			stmt.setString(1, PasswordEncryptionWithAes.encrypt(user.getUsername(), user.getPassword()));
			stmt.setInt(2, user.getUserID());

			int result = stmt.executeUpdate();

			if (result > 0) {
				return 1;
			} else {
				return 0;
			}

		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int DeleteUser(int uid) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_DELETE_USER);
			stmt.setInt(1, uid);
			int result = stmt.executeUpdate();
			if (result > 0) {
				return 1;
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public Boolean checkEmailIfExists(String email) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_CHECK_EMAIL);
			stmt.setString(1, email);
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				return true;
			} else {
				return false;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return true;
		}
	}

	public Boolean checkNumberIfExists(String number) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_CHECK_PHONE);
			stmt.setString(1, number);
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				return true;
			} else {
				return false;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return true;
		}
	}

	public Boolean checkUsernameIfExists(String username) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_CHECK_USER);
			stmt.setString(1, username);
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				return true;
			} else {
				return false;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return true;
		}
	}

	public int AddProduct(ProductModel product) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_ADD_PRODUCT);
			stmt.setString(1, product.getName());
			stmt.setInt(2, product.getPrice());
			stmt.setString(3, product.getDescription());
			stmt.setString(4, product.getCategory());
			stmt.setInt(5, product.getStock());
			stmt.setString(6, product.getImagePath());

			int result = stmt.executeUpdate();

			if (result > 0) {
				return 1;
			} else {
				return 0;
			}

		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}

	}

	public ArrayList<ProductModel> getProductsInfo(String name, String min_price, String max_price, String category) {
		ArrayList<ProductModel> products = new ArrayList<ProductModel>();

		if (name == null || name.equals("")) {
			name = "%%";
		} else {
			name = "%" + name + "%";
		}
		if (min_price == null || min_price.equals("")) {
			min_price = "0";
		}
		if (max_price == null || max_price.equals("")) {
			max_price = "99999999999";
		}
		if (category == null || category.equals("")) {
			category = "%%";
		}
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_PRODUCTS);
			stmt.setString(1, name);
			stmt.setString(2, min_price);
			stmt.setString(3, max_price);
			stmt.setString(4, category);
			ResultSet result = stmt.executeQuery();
			while (result.next()) {
				ProductModel product = new ProductModel();
				product.setProductID(result.getInt("productID"));
				product.setName(result.getString("name"));
				product.setPrice(result.getInt("price"));
				product.setDescription(result.getString("description"));
				product.setCategory(result.getString("category"));
				product.setStock(result.getInt("stock"));
				product.setImagePath(result.getString("imagePath"));
				products.add(product);
			}
			return products;
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return products;
		}
	}

	public ProductModel getProductInfo(int pid) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_PRODUCT);
			stmt.setInt(1, pid);
			ResultSet result = stmt.executeQuery();

			if (result.next()) {
				ProductModel product = new ProductModel();
				product.setProductID(result.getInt("productID"));
				product.setName(result.getString("name"));
				product.setPrice(result.getInt("price"));
				product.setDescription(result.getString("description"));
				product.setCategory(result.getString("category"));
				product.setStock(result.getInt("stock"));
				product.setImagePath(result.getString("imagePath"));
				return product;
			} else {
				ProductModel product = new ProductModel();
				product.setProductID(pid);
				return product;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			ProductModel product = new ProductModel();
			return product;
		}
	}

	public int UpdateProduct(ProductModel product) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_UPDATE_PRODUCT);
			stmt.setString(1, product.getName());
			stmt.setInt(2, product.getPrice());
			stmt.setString(3, product.getDescription());
			stmt.setString(4, product.getCategory());
			stmt.setInt(5, product.getStock());
			stmt.setString(6, product.getImagePath());
			stmt.setInt(7, product.getProductID());
			int Result = stmt.executeUpdate();

			if (Result > 0) {
				return 1;
			} else {
				return 0;
			}

		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int DeleteProduct(int pid) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_DELETE_PRODUCT);
			stmt.setInt(1, pid);
			int result = stmt.executeUpdate();
			if (result > 0) {
				return 1;
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public ArrayList<OrderModel> getOrdersInfo(String search) {
		ArrayList<OrderModel> orders = new ArrayList<OrderModel>();
		if (search == null || search.equals("")) {
			search = "%%";
		} else {
			search = "%" + search + "%";
		}
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_ORDERS);
			stmt.setString(1, search);
			ResultSet result = stmt.executeQuery();
			while (result.next()) {
				OrderModel order = new OrderModel();
				order.setOrderID(result.getInt("orderID"));
				order.setOrderDate(result.getDate("orderDate").toLocalDate());
				order.setTotal(result.getInt("total"));
				order.setStatus(result.getString("status"));
				order.setUserID(result.getInt("userID"));
				order.setUsername(result.getString("username"));
				orders.add(order);
			}
			return orders;
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return orders;
		}
	}

	public ArrayList<OrderModel> getOrdersInfo(int uid) {
		ArrayList<OrderModel> orders = new ArrayList<OrderModel>();
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_ORDERS_2);
			stmt.setInt(1, uid);
			ResultSet result = stmt.executeQuery();
			while (result.next()) {
				OrderModel order = new OrderModel();
				order.setOrderID(result.getInt("orderID"));
				order.setOrderDate(result.getDate("orderDate").toLocalDate());
				order.setTotal(result.getInt("total"));
				order.setStatus(result.getString("status"));
				order.setUserID(result.getInt("userID"));
				order.setUsername(result.getString("username"));
				orders.add(order);
			}
			return orders;
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return orders;
		}
	}

	public OrderModel getOrderInfo(int oid) {
		OrderModel order = new OrderModel();
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_ORDER);
			stmt.setInt(1, oid);
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				order.setOrderID(result.getInt("orderID"));
				order.setOrderDate(result.getDate("orderDate").toLocalDate());
				order.setTotal(result.getInt("total"));
				order.setStatus(result.getString("status"));

				PreparedStatement st = getConnection().prepareStatement(StringUtils.QUERY_GET_USER);
				st.setInt(1, result.getInt("userID"));
				ResultSet res = st.executeQuery();
				if (res.next()) {
					order.setUserID(res.getInt("userID"));
					order.setUsername(res.getString("username"));
				}

				PreparedStatement st2 = getConnection().prepareStatement(StringUtils.QUERY_GET_ORDER_DETAILS);
				st2.setInt(1, result.getInt("orderID"));
				ResultSet res2 = st2.executeQuery();
				ArrayList<OrderDetail> orderdetails = new ArrayList<OrderDetail>();
				while (res2.next()) {
					OrderDetail orderdetail = new OrderDetail();
					orderdetail.setDetailID(res2.getInt("detailID"));
					orderdetail.setQuantity(res2.getInt("quantity"));

					PreparedStatement st3 = getConnection().prepareStatement(StringUtils.QUERY_GET_PRODUCT);
					st3.setInt(1, res2.getInt("productID"));
					ResultSet res3 = st3.executeQuery();
					if (res3.next()) {
						orderdetail.setProductID(res3.getInt("productID"));
						orderdetail.setName(res3.getString("name"));
						orderdetail.setPrice(res3.getInt("price"));
						;
					}
					orderdetails.add(orderdetail);
				}

				order.setDetails(orderdetails);
			}
			return order;
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return order;
		}
	}

	public int AddOrder(OrderModel order) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_ADD_ORDER);
			stmt.setInt(1, order.getUserID());
			System.out.println(order.getUserID());
			stmt.setDate(2, Date.valueOf(order.getOrderDate()));
			stmt.setInt(3, order.getTotal());
			stmt.setString(4, order.getStatus());
			int result = stmt.executeUpdate();
			if (result > 0) {
				PreparedStatement stm = getConnection().prepareStatement(StringUtils.QUERY_GET_LATEST_ORDER);
				ResultSet resul = stm.executeQuery();
				
				if (resul.next()) {
					int oid = resul.getInt("latest");
					int ret = 0;
					for (OrderDetail detail : order.getDetails()) {
						PreparedStatement st = getConnection().prepareStatement(StringUtils.QUERY_ADD_ORDER_DETAILS);
						st.setInt(1, oid);
						st.setInt(2, detail.getProductID());
						st.setInt(3, detail.getQuantity());
						int res = st.executeUpdate();
						if (res > 0) {
							ret = 1;
						} else {
							ret = 0;
						}
					}
					return ret;
				} else {
					return 0;
				}
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int UpdateOrder(OrderModel order) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_UPDATE_ORDER);
			stmt.setString(1, order.getStatus());
			stmt.setInt(2, order.getOrderID());
			int Result = stmt.executeUpdate();

			if (Result > 0) {
				return 1;
			} else {
				return 0;
			}

		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int DeleteOrder(int oid) {
		try {
			PreparedStatement st = getConnection().prepareStatement(StringUtils.QUERY_DELETE_ORDER_DETAILS);
			st.setInt(1, oid);
			int res = st.executeUpdate();
			if (res >= 0) {
				PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_DELETE_ORDER);
				stmt.setInt(1, oid);
				int result = stmt.executeUpdate();
				if (result > 0) {
					return 1;
				} else {
					return 0;
				}
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int checkCount(String db) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_COUNT + db);
			ResultSet result = stmt.executeQuery();
			if (result.next()) { // Check if there's a result
				return result.getInt("count");
			} else {
				return 0; // Handle the case where no count is found
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return 0;
		}
	}

	public boolean checkCart(int uid) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_CART);
			stmt.setInt(1, uid);
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				return true;
			} else {
				return false;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return false;
		}
	}

	public int AddCart(int uid) {
		try {
			PreparedStatement st = getConnection().prepareStatement(StringUtils.QUERY_ADD_CART);
			st.setInt(1, uid);
			int result = st.executeUpdate();
			if (result > 0) {
				return 1;
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int AddToCart(int uid, CartItem item) {
		try {
			if (!checkCart(uid)) {
				PreparedStatement st = getConnection().prepareStatement(StringUtils.QUERY_ADD_CART);
				st.setInt(1, uid);
				st.executeUpdate();
			}
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_ADD_TO_CART);
			stmt.setInt(1, getCartInfo(uid).getCartID());
			stmt.setInt(2, item.getProductID());
			stmt.setInt(3, item.getQuantity());
			int result = stmt.executeUpdate();
			if (result > 0) {
				return 1;
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public int removeFromCart(int itemID) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_DELETE_CART_ITEM);
			stmt.setInt(1, itemID);
			int result = stmt.executeUpdate();
			if (result > 0) {
				return 1;
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	public CartModel getCartInfo(int uid) {
		CartModel cart;
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_CART);
			stmt.setInt(1, uid);
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				cart = new CartModel(result.getInt("cartID"));
				cart.setUserID(result.getInt("userID"));
				ArrayList<CartItem> items = new ArrayList<CartItem>();
				PreparedStatement st = getConnection().prepareStatement(StringUtils.QUERY_GET_CART_ITEMS);
				st.setInt(1, result.getInt("cartID"));
				ResultSet res = st.executeQuery();
				while (res.next()) {
					CartItem item = new CartItem(res.getInt("itemID"), res.getInt("quantity"));
					item.setProductID(res.getInt("productID"));
					PreparedStatement st2 = getConnection().prepareStatement(StringUtils.QUERY_GET_PRODUCT);
					st2.setInt(1, item.getProductID());
					ResultSet res2 = st2.executeQuery();
					if (res2.next()) {
						item.setName(res2.getString("name"));
						item.setPrice(res2.getInt("price"));
						item.setDescription(res2.getString("description"));
						item.setCategory(res2.getString("category"));
						item.setStock(res2.getInt("stock"));
						item.setImagePath(res2.getString("imagePath"));
					}
					items.add(item);
				}
				cart.setItem(items);
				return cart;
			} else {
				AddCart(uid);
				return getCartInfo(uid);
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			cart = new CartModel();
			return cart;
		}
	}

	public boolean checkInCart(int uid, int pid) {
		try {
			PreparedStatement stmt = getConnection().prepareStatement(StringUtils.QUERY_GET_CART_PRODS);
			stmt.setInt(1, pid);
			stmt.setInt(2, getCartInfo(uid).getCartID());
			ResultSet result = stmt.executeQuery();
			if (result.next()) {
				return true;
			} else {
				return false;
			}

		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return true;
		}
	}

	public int cartToOrder(int uid, int total) {
		try {
			CartModel cart = getCartInfo(uid);
			OrderModel order = new OrderModel();
			order.setUserID(cart.getUserID());
			order.setOrderDate(LocalDate.now());
			order.setTotal(total);
			order.setStatus("pending");
			ArrayList<OrderDetail> details = new ArrayList<OrderDetail>();
			for (CartItem item : cart.getItem()) {
				OrderDetail detail = new OrderDetail();
				detail.setQuantity(item.getQuantity());
				detail.setProductID(item.getProductID());
				detail.setPrice(item.getPrice());
				detail.setCategory(item.getCategory());
				detail.setDescription(item.getDescription());
				detail.setStock(item.getStock());
				detail.setImagePath(item.getImagePath());
				detail.setName(item.getName());
				details.add(detail);
			}
			order.setDetails(details);
			int result = AddOrder(order);
			if (result > 0) {
				for (CartItem item:cart.getItem()) {
					removeFromCart(item.getItemID());
				}
				PreparedStatement stmt=getConnection().prepareStatement(StringUtils.QUERY_DELETE_CART);
				stmt.setInt(1, uid);
				if (stmt.executeUpdate()>0) {
					return 1;
				} else {
					return 0;
				}
			} else {
				return 0;
			}
		} catch (SQLException | ClassNotFoundException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
}