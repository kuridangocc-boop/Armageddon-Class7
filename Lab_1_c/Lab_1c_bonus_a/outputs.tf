# # Explanation: Outputs are your mission report—what got built and where to find it.
# output "armageddon_lab_vpc_id" {
#   value = aws_vpc.armageddon_lab.id
# }

# output "armageddon_lab_public_subnet_ids" {
#   value = aws_subnet.armageddon_lab_public_subnets[*].id
# }

# output "armageddon_lab_private_subnet_ids" {
#   value = aws_subnet.armageddon_lab_private_subnets[*].id
# }

# output "armageddon_lab_ec2_instance_id" {
#   value = aws_instance.armageddon_lab_ec201.id
# }

# output "armageddon_lab_rds_endpoint" {
#   value = aws_db_instance.armageddon_lab_rds01.address
# }

# output "armageddon_lab_sns_topic_arn" {
#   value = aws_sns_topic.armageddon_lab_sns_topic01.arn
# }

# output "armageddon_lab_log_group_name" {
#   value = aws_cloudwatch_log_group.armageddon_lab_log_group01.name
# }