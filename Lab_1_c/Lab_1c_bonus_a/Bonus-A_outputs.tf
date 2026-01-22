#Bonus-A outputs (append to outputs.tf)

# Explanation: These outputs prove Chewbacca built private hyperspace lanes (endpoints) instead of public chaos.
output "armageddon_lab_vpce_ssm_id" {
  value = aws_vpc_endpoint.armageddon_lab_vpce_ssm01.id
}

output "armageddon_lab_vpce_logs_id" {
  value = aws_vpc_endpoint.armageddon_lab_vpce_logs01.id
}

output "armageddon_lab_vpce_secrets_id" {
  value = aws_vpc_endpoint.armageddon_lab_vpce_secrets01.id
}

output "armageddon_lab_vpce_s3_id" {
  value = aws_vpc_endpoint.armageddon_lab_vpce_s3_gw01.id
}

output "armageddon_lab_private_ec2_instance_id_bonus" {
  value = aws_instance.armageddon_lab_ec201_private_bonus.id
}

output "armageddon_lab_vpce_ec2messages_id" {
  value = aws_vpc_endpoint.armageddon_lab_vpce_ec2messages01.id
}

output "armageddon_lab_vpce_ssmmessages_id" {
  value = aws_vpc_endpoint.armageddon_lab_vpce_ssmmessages01.id
}