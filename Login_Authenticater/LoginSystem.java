import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * Console login authentication system.
 *
 * Features:
 * - Registration with username and password rules
 * - Passwords stored as salted PBKDF2-HMAC-SHA256 hashes (never in plain text)
 * - Login with a lockout after repeated failed attempts
 * - Change password while logged in
 * - Users saved to users.db between runs
 *
 * Compile: javac LoginSystem.java
 * Run: java LoginSystem
 */
public class LoginSystem {

    // ---- Settings ----------------------------------------------------------
    private static final int ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_MILLIS = 5 * 60 * 1000L;
    private static final Pattern USERNAME_RULE = Pattern.compile("[A-Za-z0-9_]{3,20}");
    private static final Path DB_FILE = Paths.get("users.db");

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    // ---- User record -------------------------------------------------------
    private static final class User {
        final String name;
        byte[] salt;
        byte[] hash;
        int iterations;
        int failedAttempts;
        long lockedUntil;

        User(String name, byte[] salt, byte[] hash, int iterations, int failedAttempts, long lockedUntil) {
            this.name = name;
            this.salt = salt;
            this.hash = hash;
            this.iterations = iterations;
            this.failedAttempts = failedAttempts;
            this.lockedUntil = lockedUntil;
        }

        String serialize() {
            return String.join(":", name, String.valueOf(iterations), B64E.encodeToString(salt),
                    B64E.encodeToString(hash), String.valueOf(failedAttempts), String.valueOf(lockedUntil));
        }

        static User parse(String line) {
            String[] p = line.split(":");
            if (p.length != 6)
                throw new IllegalArgumentException("Bad record");
            return new User(p[0], B64D.decode(p[2]), B64D.decode(p[3]),
                    Integer.parseInt(p[1]), Integer.parseInt(p[4]), Long.parseLong(p[5]));
        }
    }

    // ---- Storage and authentication ----------------------------------------
    private final Map<String, User> users = new LinkedHashMap<>();

    LoginSystem() {
        load();
    }

    private void load() {
        if (!Files.exists(DB_FILE))
            return;
        try {
            for (String line : Files.readAllLines(DB_FILE, StandardCharsets.UTF_8)) {
                if (line.isBlank())
                    continue;
                try {
                    User u = User.parse(line);
                    users.put(u.name.toLowerCase(), u);
                } catch (RuntimeException e) {
                    System.err.println("Skipped a damaged record in " + DB_FILE);
                }
            }
        } catch (IOException e) {
            System.err.println("Could not read " + DB_FILE + ": " + e.getMessage());
        }
    }

    private void save() {
        List<String> lines = new ArrayList<>();
        for (User u : users.values())
            lines.add(u.serialize());
        try {
            Files.write(DB_FILE, lines, StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("Could not save " + DB_FILE + ": " + e.getMessage());
        }
    }

    private static byte[] hashPassword(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Password hashing is not available", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Returns an error message, or null when the password is acceptable. */
    static String checkPasswordRules(String username, char[] pw) {
        String s = new String(pw);
        if (s.length() < 10)
            return "Password must be at least 10 characters.";
        if (s.length() > 128)
            return "Password must be at most 128 characters.";
        if (!s.chars().anyMatch(Character::isUpperCase))
            return "Add at least one uppercase letter.";
        if (!s.chars().anyMatch(Character::isLowerCase))
            return "Add at least one lowercase letter.";
        if (!s.chars().anyMatch(Character::isDigit))
            return "Add at least one number.";
        if (s.chars().allMatch(Character::isLetterOrDigit))
            return "Add at least one symbol, such as ! or #.";
        if (s.toLowerCase().contains(username.toLowerCase()))
            return "Password must not contain your username.";
        return null;
    }

    String register(String username, char[] password) {
        if (!USERNAME_RULE.matcher(username).matches())
            return "Username must be 3-20 characters: letters, numbers or underscore.";
        if (users.containsKey(username.toLowerCase()))
            return "That username is already taken.";
        String problem = checkPasswordRules(username, password);
        if (problem != null)
            return problem;

        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = hashPassword(password, salt, ITERATIONS);
        users.put(username.toLowerCase(), new User(username, salt, hash, ITERATIONS, 0, 0));
        save();
        return null;
    }

    /** Result of a login attempt. */
    static final class LoginResult {
        final User user;
        final String message;

        LoginResult(User user, String message) {
            this.user = user;
            this.message = message;
        }

        boolean ok() {
            return user != null;
        }
    }

    LoginResult login(String username, char[] password) {
        User u = users.get(username.toLowerCase());
        if (u == null) {
            // Do the same amount of work so timing does not reveal which usernames exist.
            hashPassword(password, new byte[SALT_BYTES], ITERATIONS);
            return new LoginResult(null, "Invalid username or password.");
        }

        long now = System.currentTimeMillis();
        if (u.lockedUntil > now) {
            long mins = (u.lockedUntil - now + 59_999) / 60_000;
            return new LoginResult(null, "Account locked after too many failed attempts. Try again in "
                    + mins + " minute" + (mins == 1 ? "" : "s") + ".");
        }

        byte[] attempt = hashPassword(password, u.salt, u.iterations);
        if (MessageDigest.isEqual(attempt, u.hash)) {
            u.failedAttempts = 0;
            u.lockedUntil = 0;
            save();
            return new LoginResult(u, "Login successful.");
        }

        u.failedAttempts++;
        if (u.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            u.lockedUntil = now + LOCK_MILLIS;
            u.failedAttempts = 0;
            save();
            return new LoginResult(null, "Too many failed attempts. The account is locked for "
                    + (LOCK_MILLIS / 60_000) + " minutes.");
        }
        save();
        int left = MAX_FAILED_ATTEMPTS - u.failedAttempts;
        return new LoginResult(null, "Invalid username or password. " + left + " attempt"
                + (left == 1 ? "" : "s") + " left before lockout.");
    }

    String changePassword(User u, char[] oldPw, char[] newPw) {
        if (!MessageDigest.isEqual(hashPassword(oldPw, u.salt, u.iterations), u.hash))
            return "Current password is incorrect.";
        String problem = checkPasswordRules(u.name, newPw);
        if (problem != null)
            return problem;
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        u.salt = salt;
        u.iterations = ITERATIONS;
        u.hash = hashPassword(newPw, salt, ITERATIONS);
        save();
        return null;
    }

    // ---- Console interface -------------------------------------------------
    private static final Scanner IN = new Scanner(System.in);

    private static String ask(String prompt) {
        System.out.print(prompt);
        return IN.hasNextLine() ? IN.nextLine().trim() : "";
    }

    /** Reads a password without echoing it when a real terminal is available. */
    private static char[] askPassword(String prompt) {
        java.io.Console console = System.console();
        if (console != null) {
            char[] pw = console.readPassword("%s", prompt);
            return pw == null ? new char[0] : pw;
        }
        System.out.print(prompt);
        return (IN.hasNextLine() ? IN.nextLine() : "").toCharArray();
    }

    private void registerFlow() {
        System.out.println("\n--- Register ---");
        String username = ask("Choose a username: ");
        char[] pw = askPassword("Choose a password: ");
        char[] confirm = askPassword("Repeat the password: ");
        try {
            if (!Arrays.equals(pw, confirm)) {
                System.out.println("The passwords do not match.");
                return;
            }
            String error = register(username, pw);
            System.out.println(error == null ? "Account created. You can log in now." : error);
        } finally {
            Arrays.fill(pw, '\0');
            Arrays.fill(confirm, '\0');
        }
    }

    private void loginFlow() {
        System.out.println("\n--- Log in ---");
        String username = ask("Username: ");
        char[] pw = askPassword("Password: ");
        LoginResult result;
        try {
            result = login(username, pw);
        } finally {
            Arrays.fill(pw, '\0');
        }
        System.out.println(result.message);
        if (result.ok())
            accountMenu(result.user);
    }

    private void accountMenu(User u) {
        System.out.println("\nWelcome, " + u.name + "!");
        while (true) {
            System.out.println("\n1) Change password");
            System.out.println("2) Log out");
            String choice = ask("Choose an option: ");
            if (choice.equals("1")) {
                char[] oldPw = askPassword("Current password: ");
                char[] newPw = askPassword("New password: ");
                try {
                    String error = changePassword(u, oldPw, newPw);
                    System.out.println(error == null ? "Password changed." : error);
                } finally {
                    Arrays.fill(oldPw, '\0');
                    Arrays.fill(newPw, '\0');
                }
            } else if (choice.equals("2")) {
                System.out.println("Logged out.");
                return;
            } else {
                System.out.println("Please choose 1 or 2.");
            }
        }
    }

    private void run() {
        System.out.println("=== Login Authentication System ===");
        while (true) {
            System.out.println("\n1) Log in");
            System.out.println("2) Register");
            System.out.println("3) Quit");
            if (!IN.hasNextLine())
                return;
            String choice = ask("Choose an option: ");
            switch (choice) {
                case "1":
                    loginFlow();
                    break;
                case "2":
                    registerFlow();
                    break;
                case "3":
                    System.out.println("Goodbye!");
                    return;
                default:
                    System.out.println("Please choose 1, 2 or 3.");
            }
        }
    }

    public static void main(String[] args) {
        new LoginSystem().run();
    }
}