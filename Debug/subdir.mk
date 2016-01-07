################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../ASTVisitor.cpp \
../Checker.cpp \
../DoubleFetchChecker-multitaint.cpp \
../DoubleFetchChecker.cpp \
../LockChecker.cpp 

OBJS += \
./ASTVisitor.o \
./Checker.o \
./DoubleFetchChecker-multitaint.o \
./DoubleFetchChecker.o \
./LockChecker.o 

CPP_DEPS += \
./ASTVisitor.d \
./Checker.d \
./DoubleFetchChecker-multitaint.d \
./DoubleFetchChecker.d \
./LockChecker.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


