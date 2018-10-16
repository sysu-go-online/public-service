package tools

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/satori/go.uuid"

	ttyModel "github.com/sysu-go-online/tty-service/model"
	userModel "github.com/sysu-go-online/user-service/model"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/sysu-go-online/public-service/types"
)

// JWTKey defines the token key
var JWTKey = "go-online"

// ROOT defines the root directory
var ROOT = "/home"

func checkFilePath(path string) bool {
	return true
}

// GetConfigContent read configure file and return the content
func GetConfigContent() *types.ConfigFile {
	// Get messages from configure file
	configureFilePath := os.Getenv("CONFI_FILE_PATH")
	if len(configureFilePath) == 0 {
		configureFilePath = "/config/config.yml"
	}
	content, err := ioutil.ReadFile(configureFilePath)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	config := new(types.ConfigFile)
	err = yaml.Unmarshal(content, config)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return config
}

// CheckEmail check if the email is valid
func CheckEmail(email string) bool {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}

// CheckUsername check username
func CheckUsername(username string) bool {
	if len(username) > 5 && len(username) < 16 {
		return true
	}
	return false
}

// HashPassword return hash of password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CompasePassword compare raw password with hashed one
func CompasePassword(raw, hashed string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw)) == nil
}

// GenerateUserName generate unique userid
func GenerateUserName() string {
	return "user_" + generateUUID()
}

// TODO: return error
func generateUUID() string {
	id, err := uuid.NewV1()
	if err != nil {
		fmt.Println(err)
	}
	return id.String()
}

// CheckJWT check whether the jwt is valid and if it is in the invalid database
func CheckJWT(jwtString string, AuthRedisClient *redis.Client) (bool, error) {
	isValid, err := ValidateToken(jwtString)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}

	has, err := userModel.IsJWTExist(jwtString, AuthRedisClient)
	return !has, err
}

// GetUserNameFromToken get message from valid token
func GetUserNameFromToken(jwtString string, AuthRedisClient *redis.Client) (bool, string) {
	if ok, _ := CheckJWT(jwtString, AuthRedisClient); !ok {
		return false, ""
	}

	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWTKey), nil
	})
	if err != nil {
		fmt.Println(err)
		return false, ""
	}
	// parse username from jwt
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username := claims["sub"]
		if username == "" {
			return false, ""
		}
		sub := string(username.(string))
		return true, sub
	} else {
		return false, ""
	}
}

// ValidateToken check the format of token
func ValidateToken(jwtString string) (bool, error) {
	// validate jwt
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(JWTKey), nil
	})
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	// parse time from jwt
	var exp int64
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expired := claims["exp"]
		if expired == nil {
			return false, nil
		}
		exp = int64(expired.(float64))
		if time.Now().Unix() > exp {
			return false, nil
		}
	} else {
		return false, nil
	}
	return true, nil
}

// GenerateJWT generate token for user
func GenerateJWT(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
		"sub": username,
		"iat": time.Now().Unix(),
		"jti": generateUUID(),
	})

	return token.SignedString([]byte(JWTKey))
}

func handleMapCommand(command []string, DomainNameRedisClient *redis.Client) (*types.PortMapping, error) {
	if len(command) <= 0 || command[0] != "map" {
		return nil, errors.New("Invalid map command")
	}
	mapping := types.PortMapping{}
	// store which flag is un used
	isUsed := make([]bool, len(command))
	for i := 0; i < len(isUsed); i++ {
		isUsed[i] = false
	}

	// scan command
	start := -1
	for i := 1; i < len(command); i++ {
		if isUsed[i] {
			continue
		}
		if command[i][0] != '-' {
			start = i
			break
		}
		switch command[i] {
		case "-p":
			// parse port number
			if i == len(command)-1 {
				return nil, errors.New("can not get port number")
			}
			next := command[i+1]
			port, err := strconv.Atoi(next)
			if err != nil || port <= 0 || port >= 65535 {
				return nil, errors.New("Invalid port number")
			}
			mapping.Port = port
			isUsed[i] = true
			isUsed[i+1] = true
		default:
			return nil, fmt.Errorf("Can not parse %s", command[i])
		}
	}
	if start == -1 {
		return nil, errors.New("can not get start up command")
	}

	if mapping.Port == 0 {
		return nil, errors.New("Can not get port number")
	}

	// distribute domain name
	cnt := 0
	for {
		if cnt == 5 {
			return nil, errors.New("Can not get suitable domain name")
		}
		uuid := generateUUID()
		if has, err := ttyModel.IsUUIDExists(uuid, DomainNameRedisClient); err == nil {
			if has {
				cnt++
				continue
			} else {
				mapping.DomainName = uuid
				break
			}
		} else {
			return nil, err
		}
	}
	// parse command
	var userCommand string
	for i := start; i < len(command); i++ {
		userCommand += command[i] + " "
	}
	mapping.Command = userCommand
	return &mapping, nil
}

// ParseSystemCommand parse command start with go-online
func ParseSystemCommand(command []string, DomainNameRedisClient *redis.Client) (*types.PortMapping, error) {
	for i := 0; i < len(command); i++ {
		if len(command[i]) == 0 {
			command = append(command[:i], command[i+1:]...)
			i--
		}
	}
	if len(command) < 0 || command[0] != "go-online" {
		return nil, errors.New("Invalid command")
	}
	switch command[1] {
	// map port
	case "map":
		return handleMapCommand(command[1:], DomainNameRedisClient)
	default:
		return nil, errors.New("Invalid command")
	}
}
