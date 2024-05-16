using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.API.Migrations
{
    /// <inheritdoc />
    public partial class Edditedthetables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "37d01b7e-244c-4516-b0da-d5364c784cce");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "4fd0979d-c9d9-4c88-8e84-d3da71a502ab");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "90711fd9-160c-4e36-b25c-34764bda4150");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "073e8a0f-f22e-4e67-ab69-69135bd53a14", "2", "User", "User" },
                    { "0e2377d0-8bd6-423d-b8b0-7054dfefcc75", "3", "HR", "HR" },
                    { "323d29f4-a146-4075-92a9-0025e385a2bc", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "073e8a0f-f22e-4e67-ab69-69135bd53a14");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "0e2377d0-8bd6-423d-b8b0-7054dfefcc75");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "323d29f4-a146-4075-92a9-0025e385a2bc");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "37d01b7e-244c-4516-b0da-d5364c784cce", "2", "User", "User" },
                    { "4fd0979d-c9d9-4c88-8e84-d3da71a502ab", "1", "Admin", "Admin" },
                    { "90711fd9-160c-4e36-b25c-34764bda4150", "3", "HR", "HR" }
                });
        }
    }
}
