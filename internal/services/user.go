package service

import (
	"context"
	"errors"
	"fmt"
	"project/internal/models"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

func (s *Service) UserLogin(ctx context.Context, userData models.NewUser) (jwt.RegisteredClaims, error) {
	fu, err := s.UserRepo.Userbyemail(ctx ,userData.Email)	
	if err != nil {
		log.Error().Err(err).Msg("couldnot find user")
		return jwt.RegisteredClaims{}, errors.New("user login failed")
	}
	fmt.Println(fu)
	err = bcrypt.CompareHashAndPassword([]byte(fu.PasswordHash), []byte(userData.Password))
	if err != nil {
		log.Error().Err(err).Msg("password of user incorrect")
		return jwt.RegisteredClaims{}, errors.New("user login failed")
	}
	c := jwt.RegisteredClaims{
		Issuer:    "service project",
		Subject:   strconv.FormatUint(uint64(fu.ID), 10),
		Audience:  jwt.ClaimStrings{"users"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	fmt.Println(c)
	return c,nil
}

	// // checcking the email in the db
	// var userDetails models.User
	// userDetails, err := s.UserRepo.Userbyemail(ctx, userData.Email)
	// if err != nil {
	// 	return "", err
	// }

	// // comaparing the password and hashed password
	// hashedPass, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	// if err != nil {
	// 	log.Error().Msg("error occured in hashing password")
	// 	return jwt.RegisteredClaims{}, errors.New("hashing password failed")
	// }

	// // setting up the claims
	// claims := jwt.RegisteredClaims{
	// 	Issuer:    "job portal project",
	// 	Subject:   strconv.FormatUint(uint64(userDetails.ID), 10),
	// 	Audience:  jwt.ClaimStrings{"users"},
	// 	ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	// 	IssuedAt:  jwt.NewNumericDate(time.Now()),
	// }

	// token, err := s.auth.GenerateToken(claims)
	// if err != nil {
	// 	return "", err
	// }

	// return token, nil



func (s *Service) UserSignup(ctx context.Context, userData models.NewUser) (models.User, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Msg("error occured in hashing password")
		return models.User{}, errors.New("hashing password failed")
	}
	userDetails := models.User{
		Username:     userData.Username,
		Email:        userData.Email,
		PasswordHash: string(hashedPass),
	}
	userDetails, err = s.UserRepo.CreateUser(ctx, userDetails)
	if err != nil {
		return models.User{}, err
	}
	return userDetails, nil
}
