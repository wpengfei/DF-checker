################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../df\ test\ case/testdf.o \
../df\ test\ case/testflow.o \
../df\ test\ case/testlock.o \
../df\ test\ case/testmem.o 

C_SRCS += \
../df\ test\ case/testdf.c \
../df\ test\ case/testflow.c \
../df\ test\ case/testlock.c \
../df\ test\ case/testmem.c 

OBJS += \
./df\ test\ case/testdf.o \
./df\ test\ case/testflow.o \
./df\ test\ case/testlock.o \
./df\ test\ case/testmem.o 

C_DEPS += \
./df\ test\ case/testdf.d \
./df\ test\ case/testflow.d \
./df\ test\ case/testlock.d \
./df\ test\ case/testmem.d 


# Each subdirectory must supply rules for building sources it contributes
df\ test\ case/testdf.o: ../df\ test\ case/testdf.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"df test case/testdf.d" -MT"df\ test\ case/testdf.d" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

df\ test\ case/testflow.o: ../df\ test\ case/testflow.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"df test case/testflow.d" -MT"df\ test\ case/testflow.d" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

df\ test\ case/testlock.o: ../df\ test\ case/testlock.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"df test case/testlock.d" -MT"df\ test\ case/testlock.d" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

df\ test\ case/testmem.o: ../df\ test\ case/testmem.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"df test case/testmem.d" -MT"df\ test\ case/testmem.d" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


